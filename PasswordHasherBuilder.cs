namespace Sisusa.Security;

/// <summary>
/// Builder for creating a <see cref="PasswordHasher"/> instance in a Fluent manner.
/// </summary>
public class PasswordHasherBuilder
{

    //public int SaltLength { get; private set; }

    /// <summary>
    /// The number of iterations to use in generating the hash.
    /// </summary>
    private int IterationCount { get; set; } = 150_000;

    /// <summary>
    /// The max length of the resulting hash.
    /// </summary>
    private int MaxHashLength { get; set; } = 64;

    /// <summary>
    /// Sets the max length of the password hash.
    /// </summary>
    /// <param name="maxHashLength">Chosen max length of the password hash.</param>
    /// <returns>Current instance for further operations.</returns>
    public PasswordHasherBuilder UseMaxHashLength(int maxHashLength)
    {
        MaxHashLength = maxHashLength;
        return this;
    }

    /// <summary>
    /// Sets the number of iterations to use when generating the hash.
    /// </summary>
    /// <param name="iterations">Number of iterations for the encryption algorithm to run.</param>
    /// <returns>Current instance for further operations.</returns>
    public PasswordHasherBuilder UseSoManyIterations(int iterations)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(iterations);
        this.IterationCount = iterations;
        return this;
    }

    /// <summary>
    /// Builds a <see cref="PasswordHasher"/> instance from the specified parameter.
    /// </summary>
    /// <returns>Created instance.</returns>
    public PasswordHasher Build()
    {
        return new(MaxHashLength, IterationCount);
    }
}
