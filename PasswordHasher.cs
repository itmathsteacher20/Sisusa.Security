using System.Security.Cryptography;

namespace Sisusa.Security;

/// <summary>
/// Utility for generating password hashes using a random salt value.
/// </summary>
/// <param name="maxHashLength">The maximum length of the generated hash.</param>
/// <param name="maxIterations">The number of iterations to run when generating the hash using the chosen encryption algorithm.</param>
public class PasswordHasher(int maxHashLength = 64, int maxIterations = 100_000)
{
    

    /// <summary>
    /// The maximum hash length
    /// </summary>
    private int HashLength { get; set; } = maxHashLength;

    /// <summary>
    /// The number of iterations to use in generating the hash.
    /// </summary>
    private int Iterations { get; set; } = maxIterations;

    //private int MaxSaltLength { get; set; } = maxSaltLength;

    /// <summary>
    /// Fixed length of the salt value.
    /// </summary>
    private const int SALT_LENGTH = 32;

    public static PasswordHasherBuilder CreateBuilder()=> new();

    public static PasswordHasher DefaultInstance => new();

    /// <summary>
    /// Generates a hash for the given password.
    /// </summary>
    /// <param name="password">Password to hash.</param>
    /// <returns>The hashed password including the salt used.</returns>
    public HashedPassword GetHash(string password)
    {
        var saltHash = GenerateSalt(SALT_LENGTH);
        var passHash = HashPassword(password, saltHash);

        return new HashedPassword(
            Convert.ToBase64String(HashPassword(password, saltHash)),
            Convert.ToBase64String(saltHash));
    }

    /// <summary>
    /// Generates a hash for the given password and salt.
    /// </summary>
    /// <param name="password">Plaintext password to hash.</param>
    /// <param name="saltBytes">Salt to use in hashing the password.</param>
    /// <returns>Byte array containing hashed password.</returns>
    internal byte[] HashPassword(string password, byte[] saltBytes)
    {
        ArgumentNullException.ThrowIfNullOrWhiteSpace(password);
        ArgumentNullException.ThrowIfNull(saltBytes);

        using var hasher = new Rfc2898DeriveBytes(
            password,
            saltBytes,
            Iterations,
            HashAlgorithmName.SHA3_512
            );
        
        return hasher.GetBytes(HashLength);
    }

    /// <summary>
    /// Checks the given password against an existing hashed password.
    /// </summary>
    /// <param name="password">The plaintext password to validate.</param>
    /// <param name="existingHash">The existing hashed password to compare against.</param>
    /// <returns>True if the password is valid or matches, false otherwise.</returns>
    public bool IsValidPassword(string password, HashedPassword existingHash)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(password);
        ArgumentNullException.ThrowIfNull(existingHash);

        var expectedHash = HashPassword(
            password, 
            Convert.FromBase64String(existingHash.PasswordSalt)
            );
        var storedHash = Convert.FromBase64String(existingHash.PasswordHash);
        return CryptographicOperations.FixedTimeEquals(storedHash, expectedHash);   
    }

    /// <summary>
    /// Generates a random salt of the specified length.
    /// </summary>
    /// <param name="maxLength">Max length of the salt to generate</param>
    /// <returns>Random bytes representing salt value.</returns>
    internal static byte[] GenerateSalt(int maxLength)
    {
        byte[] salt = new byte[maxLength];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(salt, 0, salt.Length);
        }
        return salt;
    }
}
