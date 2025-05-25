using System.Text.RegularExpressions;

namespace Sisusa.Security
{
public partial class PasswordPolicy
    {
        internal class PasswordMeetsPolicy(string passwordToCheck)
        {
            readonly bool hasDigit = Regex.Match(passwordToCheck, @"(?=.*\d)").Success;
            readonly bool hasUpperCase = Regex.Match(passwordToCheck, @"(?=.*[A-Z])").Success;
            readonly bool hasLowerCase = Regex.Match(passwordToCheck, @"(?=.*[a-z])").Success;
            readonly bool hasSymbols = Regex.Match(passwordToCheck, @"(?=.*[!@#$%^&*()_+{}|:""<>?`~\[\];',./])").Success;
            readonly bool meetsMinLength = passwordToCheck.Length >= 8;

            internal bool HasDigit() => hasDigit;
            internal bool HasUpperCase() => hasUpperCase;
            internal bool HasLowerCase() => hasLowerCase;
            internal bool HasSymbols() => hasSymbols;
            internal bool MeetsMinLength(int minLength) => meetsMinLength && passwordToCheck.Length >= minLength;

            internal bool MeetsAll()
            {
                return hasDigit &&
                    hasUpperCase &&
                    hasLowerCase &&
                    hasSymbols &&
                    meetsMinLength;
            }
        }
    }
}
