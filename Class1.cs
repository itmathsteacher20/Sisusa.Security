namespace Sisusa.Security;

public class Class1
{

}


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

    public HashedPassword(string passwordHash, string passwordSalt)
    {
        ArgumentNullException.ThrowIfNullOrWhiteSpace(passwordHash);
        ArgumentNullException.ThrowIfNullOrWhiteSpace(passwordSalt);

        this.PasswordHash = passwordHash;
        this.PasswordSalt = passwordSalt;
    }
}
