namespace Sisusa.Security
{
    /// <summary>
    /// A password policy specifies the rules for acceptable passwords.
    /// </summary>
    public partial class PasswordPolicy
    {
        /// <summary>
        /// The minimum length of the password.
        /// </summary>
        public int MinimumLength { get; init; }

        /// <summary>
        /// Indicates whether the password must contain at least one uppercase letter.
        /// </summary>
        public bool RequireUppercaseLetter { get; init; }

        /// <summary>
        /// Indicates whether the password must contain at least one lowercase letter.
        /// </summary>
        public bool RequireLowercaseLetter { get; init; }

        /// <summary>
        /// Indicates whether the password must contain at least one digit.
        /// </summary>
        public bool RequireDigit { get; init; }

        /// <summary>
        /// Indicates whether the password must contain at least one special character.
        /// </summary>
        public bool RequireSpecialCharacter { get; init; }

        /// <summary>
        /// Initializes a new instance of the PasswordPolicy class with the specified parameters.
        /// </summary>
        /// <param name="minimumLength">Minimum length of the password.</param>
        /// <param name="requireUppercase">whether the password should contain at least one uppercase letter.</param>
        /// <param name="requireLowercase">Whether the password must have at least one lowercase letter.</param>
        /// <param name="requireDigit">Whether the password must contain at least one digit.</param>
        /// <param name="requireSpecialCharacter">Whether the password must contain at least one special charracter.</param>
        public PasswordPolicy(int minimumLength = 8, bool requireUppercase = true, bool requireLowercase = true, bool requireDigit = true, bool requireSpecialCharacter = true)
        {
            MinimumLength = minimumLength;
            RequireUppercaseLetter = requireUppercase;
            RequireLowercaseLetter = requireLowercase;
            RequireDigit = requireDigit;
            RequireSpecialCharacter = requireSpecialCharacter;
        }

        /// <summary>
        /// Creates a builder to use in creating the password policy
        /// </summary>
        /// <returns>Builder to create a passwordPolicy in fluent style.</returns>
        public static PolicyBuilder CreateBuilder() => new(); 

        public bool IsMetBy(string password, out List<(string Property, string Reason)> errors)
        {
            var policyCheck = new PasswordMeetsPolicy(password);

            if (policyCheck.MeetsAll())
            {
                errors = [];
                return true;
            }
            

            var checkDict = GetCheckDict();

            var expectTrue = GetExpectTrueDict(policyCheck);

            errors = [];

            if (MinimumLength > 0 && policyCheck.MeetsMinLength(MinimumLength) == false)
            {
                errors.Add((nameof(MinimumLength), $"Password must be at least {MinimumLength} characters long."));
            }

            foreach (var check in checkDict)
            {
                Console.WriteLine($"Property: {check.Key} \t Expected: {expectTrue[check.Key]} \t Actual: {check.Value}");
                if (check.Value != expectTrue[check.Key])
                {
                    errors.Add((check.Key, $"Password must contain at least one {check.Key}."));
                }
            }
            return errors.Count == 0;
        }

        private Dictionary<string, bool> GetCheckDict()
        {
            var checkDict = new Dictionary<string, bool>();

            if (RequireDigit)
                checkDict.Add(GetPropertyNameInReadableForm(nameof(RequireDigit)), RequireDigit);
            if (RequireLowercaseLetter)
                checkDict.Add(GetPropertyNameInReadableForm(nameof(RequireLowercaseLetter)), RequireLowercaseLetter);
            if (RequireUppercaseLetter)
                checkDict.Add(GetPropertyNameInReadableForm(nameof(RequireUppercaseLetter)), RequireUppercaseLetter);
            if (RequireSpecialCharacter)
                checkDict.Add(GetPropertyNameInReadableForm(nameof(RequireSpecialCharacter)), RequireSpecialCharacter);

            return checkDict;
        }

        private Dictionary<string, bool> GetExpectTrueDict(PasswordMeetsPolicy policyCheck)
        {
            var theExpectedTrueDict = new Dictionary<string, bool>();
            foreach (var check in GetCheckDict())
            {
                if (check.Value == true)
                {
                    theExpectedTrueDict.Add(check.Key, GetPropertyValue(check.Key, policyCheck));
                }
            }
            return theExpectedTrueDict;
        }

        private static string GetPropertyNameInReadableForm(string policyRequirement)
        {

            if (policyRequirement.Contains("Require", StringComparison.InvariantCultureIgnoreCase))
            {
                return policyRequirement.Replace("Require", "", StringComparison.InvariantCultureIgnoreCase);
            }
            return policyRequirement;
        }

        private bool GetPropertyValue(string propertyName, PasswordMeetsPolicy passwordMeetsPolicy)
        {
            if (string.IsNullOrEmpty(propertyName))
            {
                throw new ArgumentNullException(nameof(propertyName));
            }
            if (passwordMeetsPolicy != null)
            {
                if (String.Equals(propertyName, GetPropertyNameInReadableForm(nameof(RequireDigit)), StringComparison.OrdinalIgnoreCase))
                {
                    return passwordMeetsPolicy.HasDigit();
                }
                if (String.Equals(propertyName, GetPropertyNameInReadableForm(nameof(RequireLowercaseLetter)), StringComparison.OrdinalIgnoreCase))
                {
                    return passwordMeetsPolicy.HasLowerCase();
                }
                if (String.Equals(propertyName, GetPropertyNameInReadableForm(nameof(RequireUppercaseLetter)), StringComparison.OrdinalIgnoreCase))
                {
                    return passwordMeetsPolicy.HasUpperCase();
                }
                if (String.Equals(propertyName, GetPropertyNameInReadableForm(nameof(RequireSpecialCharacter)), StringComparison.OrdinalIgnoreCase))
                {
                    return passwordMeetsPolicy.HasSymbols();
                }
                if (String.Equals(propertyName, GetPropertyNameInReadableForm(nameof(MinimumLength)), StringComparison.OrdinalIgnoreCase))
                {
                    return passwordMeetsPolicy.MeetsMinLength(MinimumLength);
                }
            }
            else
            {
                throw new ArgumentNullException(nameof(passwordMeetsPolicy));
            }
            return false;
        }


    }
}
