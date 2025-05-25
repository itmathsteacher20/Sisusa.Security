namespace Sisusa.Security;

/// <summary>
/// A password after it's been hashed, includes the salt used to hash it.
/// </summary>
public class HashedPassword
{
    /// <summary>
    /// The hashed password.
    /// </summary>
    public string PasswordHash { get; init; } = string.Empty;

    /// <summary>
    /// The salt used in hashing the password.
    /// </summary>
    public string PasswordSalt { get; init; } = string.Empty;

    /// <summary>
    /// Creates a new instance of <see cref="HashedPassword"/> with the specified hash and salt values.
    /// </summary>
    /// <param name="passwordHash">The hashed password.</param>
    /// <param name="passwordSalt">The salt used to hash the password.</param>
    public HashedPassword(string passwordHash, string passwordSalt)
    {
        ArgumentNullException.ThrowIfNullOrWhiteSpace(passwordHash);
        ArgumentNullException.ThrowIfNullOrWhiteSpace(passwordSalt);

        this.PasswordHash = passwordHash;
        this.PasswordSalt = passwordSalt;
    }
}
