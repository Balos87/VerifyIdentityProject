using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Microsoft.Maui.Storage;

namespace VerifyIdentityProject.Helpers
{

    public class Secrets
    {
        public string MRZ_NUMBERS { get; set; }
    }
    public class GetSecrets
    {
        public static Secrets FetchSecrets()
        {
            // Get the path to the secret.json file in the output directory
            var secretsFilePath = Path.Combine(FileSystem.AppDataDirectory, "secrets.json");

            if (File.Exists(secretsFilePath))
            {
                // Read the JSON content from the file
                var json = File.ReadAllText(secretsFilePath);

                // Deserialize the JSON content into the Secrets object
                return JsonConvert.DeserializeObject<Secrets>(json);
            }
            else
            {
                throw new FileNotFoundException("The secrets.json file was not found.");
            }
        }
    }
}
