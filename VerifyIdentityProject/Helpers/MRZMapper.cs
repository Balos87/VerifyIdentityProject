using System.Collections.Generic;

namespace VerifyIdentityProject.Helpers
{
    public static class MRZMapper
    {
        public static Dictionary<string, string> MapToStandardKeys(Dictionary<string, string> mrzData)
        {
            var mapped = new Dictionary<string, string>();

            if (mrzData.TryGetValue("Given Names", out var firstName))
                mapped["FirstName"] = firstName;

            if (mrzData.TryGetValue("Surname", out var lastName))
                mapped["LastName"] = lastName;

            if (mrzData.TryGetValue("Personal Number", out var ssn))
                mapped["SSN"] = ssn;

            // we could also copy rest of original fields.
            foreach (var kvp in mrzData)
            {
                if (!mapped.ContainsKey(kvp.Key))
                    mapped[kvp.Key] = kvp.Value;
            }

            return mapped;
        }
    }
}
