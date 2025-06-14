# Sisusa.Security Password Utilities Documentation

## Overview

The Sisusa.Security library provides robust password security utilities including secure hashing, validation, and policy enforcement. This documentation covers the `PasswordHasher` and `PasswordPolicy` classes that work together to provide comprehensive password security.

## PasswordHasher

### Features
- Uses PBKDF2 with SHA3-512 for secure password hashing
- Generates random salts for each password
- Configurable iterations (default: 100,000)
- Configurable hash length (default: 64 bytes)
- Time-constant comparison to prevent timing attacks

### Usage Examples

#### Basic Hashing and Verification
```csharp
var hasher = PasswordHasher.DefaultInstance;

// Hash a new password
var hashedPassword = hasher.GetHash("MySecurePassword123!");

// Verify a password later
bool isValid = hasher.IsValidPassword("MySecurePassword123!", hashedPassword);
```

#### Custom Configuration
```csharp
var hasher = PasswordHasher.CreateBuilder()
    .UseMaxHashLength(128)
    .UseSoManyIterations(250_000)
    .Build();
```

### Why This Solution is Superior

1. **Security Best Practices**: Uses industry-standard PBKDF2 with SHA3-512 which is currently NIST recommended
2. **Per-Password Salting**: Each password gets a unique 32-byte salt
3. **Configurable Work Factor**: Iterations can be increased as hardware improves
4. **Timing Attack Protection**: Uses `FixedTimeEquals` for secure comparison
5. **Modern Algorithms**: Uses SHA3-512 instead of older SHA1/SHA256 variants

**Real World Scenario**: When your database is compromised, the per-password salts and high iteration counts make brute force attacks impractical.

## PasswordPolicy

### Features
- Configurable complexity requirements:
  - Minimum length (default: 8)
  - Uppercase letters (default: required)
  - Lowercase letters (default: required)
  - Digits (default: required)
  - Special characters (default: required)
- Detailed validation feedback
- Fluent builder interface

### Usage Examples

#### Basic Policy Checking
```csharp
var policy = new PasswordPolicy(
    minimumLength: 12,
    requireSpecialCharacter: true);

bool isValid = policy.IsMetBy("Password123!", out var errors);
```

#### Using Builder Pattern
```csharp
var strictPolicy = PasswordPolicy.CreateBuilder()
    .MustHaveMinimumLength(16)
    .MustIncludeSpecialCharacters()
    .MustIncludeNumber()
    .MustHaveUpperCase()
    .MustHaveLowerCase()
    .Build();
```

#### Getting Detailed Errors
```csharp
if (!policy.IsMetBy("weak", out var errors))
{
    foreach (var error in errors)
    {
        Console.WriteLine($"{error.Property}: {error.Reason}");
    }
}
```

### Why This Solution is Superior

1. **Flexible Configuration**: Tailor policies to your exact security requirements
2. **Detailed Feedback**: Get specific reasons why a password fails
3. **Modern Requirements**: Enforces best practices beyond just length
4. **Readable Code**: Fluent interface makes policy creation clear
5. **Extensible Design**: Easy to add new validation rules

**Real World Scenario**: When onboarding new users, you can ensure they create strong passwords while providing clear guidance when their attempts don't meet requirements, improving both security and user experience.

## Combined Usage Example

```csharp
// Configure strict policy
var passwordPolicy = PasswordPolicy.CreateBuilder()
    .MustHaveMinimumLength(12)
    .MustIncludeSpecialCharacters()
    .MustIncludeNumber()
    .MustHaveUpperCase()
    .MustHaveLowerCase()
    .Build();

// Configure secure hasher
var passwordHasher = PasswordHasher.CreateBuilder()
    .UseSoManyIterations(150_000)
    .Build();

// User registration flow
string userPassword = "SecurePassword123!";
if (passwordPolicy.IsMetBy(userPassword, out var errors))
{
    var hashedPassword = passwordHasher.GetHash(userPassword);
    // Store hashedPassword.PasswordHash and hashedPassword.PasswordSalt
}
else
{
    // Show errors to user
}
```

## Best Practices

1. **Iteration Count**: Start with at least 100,000 iterations and increase every 2 years
2. **Password Policy**: Require at least 12 characters and 4 character types (upper, lower, number, symbol)
3. **Error Messages**: Show specific requirements to users when passwords fail
4. **Storage**: Store only the hash and salt - never the raw password
5. **Updates**: Periodically rehash passwords when increasing iteration counts

This library provides a complete solution for password security that exceeds most industry standards while remaining flexible enough to adapt to your specific security requirements.