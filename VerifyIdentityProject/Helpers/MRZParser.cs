using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VerifyIdentityProject.Helpers
{
    public static class MRZParser
    {
        public class MRZData
        {
            public string DocumentType { get; set; }
            public string IssuingCountry { get; set; }
            public string Surname { get; set; }
            public string GivenNames { get; set; }
            public string PassportNumber { get; set; }
            public char PassportNumberCheckDigit { get; set; }
            public string Nationality { get; set; }
            public string BirthDate { get; set; }
            public char BirthDateCheckDigit { get; set; }
            public string Gender { get; set; }
            public string ExpiryDate { get; set; }
            public char ExpiryDateCheckDigit { get; set; }
            public string PersonalNumber { get; set; }
            public char PersonalNumberCheckDigit { get; set; }
            public char FinalCheckDigit { get; set; }

            // Formatted Date properties for easier consumption
            public DateTime? ParsedBirthDate => ParseDate(BirthDate);
            public DateTime? ParsedExpiryDate => ParseDate(ExpiryDate);
        }

        public static MRZData ParseMRZ(string cleanMRZ)
        {


            // Split MRZ-data into lines
            string[] lines = cleanMRZ.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
            if (lines.Length < 2)
                throw new InvalidOperationException("MRZ måste innehålla minst två rader.");

            // Ensure each line is exactly 44 characters long
            string line1 = lines[0].PadRight(44, '<');
            string line2 = lines[1].PadRight(44, '<');

            // Handle optional third line
            string fullNamePart = line1.Substring(5);
            string[] nameParts = fullNamePart.Split(new[] { "<<" }, StringSplitOptions.None);
            string surname = nameParts[0].Replace("<", "").Trim();
            string givenNames = nameParts.Length > 1 ? nameParts[1].Replace("<", " ").Trim() : "";

            var mrzData = new MRZData
            {
                DocumentType = line1.Substring(0, 2).Replace("<", "").Trim(),
                IssuingCountry = line1.Substring(2, 3).Trim(),
                Surname = surname,
                GivenNames = givenNames,
                PassportNumber = line2.Substring(0, 9).Replace("<", "").Trim(),
                PassportNumberCheckDigit = line2[9],
                Nationality = line2.Substring(10, 3).Trim(),
                BirthDate = line2.Substring(13, 6).Trim(),
                BirthDateCheckDigit = line2[19],
                Gender = line2.Substring(20, 1).Trim(),
                ExpiryDate = line2.Substring(21, 6).Trim(),
                ExpiryDateCheckDigit = line2[27],
                PersonalNumber = line2.Substring(28, 14).Replace("<", "").Trim(),
                PersonalNumberCheckDigit = line2[42],
                FinalCheckDigit = line2[43]
            };

            return mrzData;
        }

        private static DateTime? ParseDate(string date)
        {
            if (string.IsNullOrEmpty(date) || date.Length != 6)
                return null;

            try
            {
                int year = int.Parse(date.Substring(0, 2));
                int month = int.Parse(date.Substring(2, 2));
                int day = int.Parse(date.Substring(4, 2));

                // Handle two-digit year
                int fullYear = year + (year >= 50 ? 1900 : 2000);

                return new DateTime(fullYear, month, day);
            }
            catch
            {
                return null;
            }
        }

        // Helper method to convert MRZData to a dictionary
        public static Dictionary<string, string> ToDictionary(MRZData data)
        {
            return new Dictionary<string, string>
        {
            { "Document Type", data.DocumentType },
            { "Issuing Country", data.IssuingCountry },
            { "Surname", data.Surname },
            { "Given Names", data.GivenNames },
            { "Full Name", $"{data.Surname} {data.GivenNames}".Trim() },
            { "Passport Number", data.PassportNumber },
            { "Passport Number Check Digit", data.PassportNumberCheckDigit.ToString() },
            { "Nationality", data.Nationality },
            { "Birth Date", data.BirthDate },
            { "Birth Date Formatted", data.ParsedBirthDate?.ToString("yyyy-MM-dd") ?? "" },
            { "Birth Date Check Digit", data.BirthDateCheckDigit.ToString() },
            { "Gender", data.Gender },
            { "Expiry Date", data.ExpiryDate },
            { "Expiry Date Formatted", data.ParsedExpiryDate?.ToString("yyyy-MM-dd") ?? "" },
            { "Expiry Date Check Digit", data.ExpiryDateCheckDigit.ToString() },
            { "Personal Number", data.PersonalNumber },
            { "Personal Number Check Digit", data.PersonalNumberCheckDigit.ToString() },
            { "Final Check Digit", data.FinalCheckDigit.ToString() }
        };
        }
    }
}