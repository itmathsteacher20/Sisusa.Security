namespace Sisusa.Security
{
public partial class PasswordPolicy
    {
        /// <summary>
        /// Utility class used to build a <see cref="PasswordPolicy"/> in a fluent manner.
        /// </summary>
        public class PolicyBuilder
        {
            private bool mustHaveUpperCase;
            private bool mustHaveLowerCase;
            private bool mustHaveDigit;
            private bool mustHaveSpecialCharacter;
            private int minLength = 8;
            public PolicyBuilder() { }

            /// <summary>
            /// Sets the minimum length of the password.
            /// </summary>
            /// <param name="length">The mininum length of the password.</param>
            /// <returns>Current builder instance.</returns>
            public PolicyBuilder MustHaveMinimumLength(int length)
            {
                minLength = length;
                return this;
            }

            /// <summary>
            /// Sets the password to require at least one special character.
            /// </summary>
            /// <returns>Current builder instance.</returns>
            public PolicyBuilder MustIncludeSpecialCharacters()
            {
                mustHaveSpecialCharacter = true;
                return this;
            }


            /// <summary>
            /// Sets the password to require at least one number.
            /// </summary>
            /// <returns>Current builder instance.</returns>
            public PolicyBuilder MustIncludeNumber()
            {
                mustHaveDigit = true;
                return this;
            }

            /// <summary>
            /// Sets the password to require at least one upper case letter.
            /// </summary>
            /// <returns>Current builder instance.</returns>
            public PolicyBuilder MustHaveUpperCase()
            {
                mustHaveUpperCase = true;
                return this;
            }

            /// <summary>
            /// Sets the password to require at least one lowercase letter.
            /// </summary>
            /// <returns>Current builder instance.</returns>
            public PolicyBuilder MustHaveLowerCase()
            {
                mustHaveLowerCase = true;
                return this;
            }

            public PasswordPolicy Build()
            {
                return new PasswordPolicy(
                    minLength,
                    mustHaveUpperCase,
                    mustHaveLowerCase,
                    mustHaveDigit,
                    mustHaveSpecialCharacter);
            }
        }
    }
}
