//using System;
//using System.IO;
//using System.Text.Json;
//using VerifyIdentityProject.Helpers;

//public class SecretsManager
//{
//    private readonly string _secretsFilePath;

//    public SecretsManager(string secretsFilePath)
//    {
//        _secretsFilePath = secretsFilePath;

//    }

//    public void SetMrzNumbers(string newMrzNumbers)
//    {
//        Secrets secrets;

//        // Check if the file exists; if not, create a new instance of Secrets.
//        if (File.Exists(_secretsFilePath))
//        {
//            string json = File.ReadAllText(_secretsFilePath);
//            // Deserialize the JSON into a Secrets object.
//            secrets = JsonSerializer.Deserialize<Secrets>(json) ?? new Secrets();
//        }
//        else
//        {
//            secrets = new Secrets();
//        }

//        // Update the MRZ_NUMBERS property.
//        secrets.MRZ_NUMBERS = newMrzNumbers;

//        // Serialize the object back to JSON with indentation for readability.
//        var options = new JsonSerializerOptions { WriteIndented = true };
//        string updatedJson = JsonSerializer.Serialize(secrets, options);

//        // Write the updated JSON back to the file.
//        File.WriteAllText(_secretsFilePath, updatedJson);

//        Console.WriteLine("MRZ_NUMBERS updated successfully.");
//    }
//}
using System;
using System.IO;
using System.Text.Json;
using VerifyIdentityProject.Helpers;

public class SecretsManager
{
    private readonly string _secretsFilePath;

    public SecretsManager(string secretsFilePath)
    {
        _secretsFilePath = secretsFilePath;

        // Ensure file exists
        if (!File.Exists(_secretsFilePath))
        {
            var defaultSecrets = new Secrets { MRZ_NUMBERS = "", LOCAL_SERVER = "", API_URL = "" };
            SaveSecrets(defaultSecrets);
        }
    }

    public void SetMrzNumbers(string newMrzNumbers)
    {
        var secrets = LoadSecrets();
        secrets.MRZ_NUMBERS = newMrzNumbers;
        SaveSecrets(secrets);

        Console.WriteLine($"MRZ updated: {newMrzNumbers}");
    }


    private Secrets LoadSecrets()
    {
        if (File.Exists(_secretsFilePath))
        {
            string json = File.ReadAllText(_secretsFilePath);
            return JsonSerializer.Deserialize<Secrets>(json) ?? new Secrets();
        }
        return new Secrets();
    }

    private void SaveSecrets(Secrets secrets)
    {
        var options = new JsonSerializerOptions { WriteIndented = true };
        string updatedJson = JsonSerializer.Serialize(secrets, options);
        File.WriteAllText(_secretsFilePath, updatedJson);
    }
}

