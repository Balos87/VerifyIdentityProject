using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace VerifyIdentityProject.Helpers
{
    public class CopySecrets
    {
        public async Task CopySecretFileToAppData()
        {
            var secretJsonFileName = "secrets.json"; // Name of the JSON file
            var appDataPath = Path.Combine(FileSystem.AppDataDirectory, secretJsonFileName);

            // Check if the file already exists in AppDataDirectory
            if (!File.Exists(appDataPath))
            {
                // If not, copy it from the resources folder
                var assembly = Assembly.GetExecutingAssembly();
                var resourceName = $"VerifyIdentityProject.Resources.{secretJsonFileName}"; 

                using (var stream = assembly.GetManifestResourceStream(resourceName))
                {
                    if (stream != null)
                    {
                        using (var fileStream = new FileStream(appDataPath, FileMode.Create))
                        {
                            await stream.CopyToAsync(fileStream);
                        }
                    }
                }
            }

            // Now you can read the file from the AppDataDirectory
            if (File.Exists(appDataPath))
            {
                var jsonContent = File.ReadAllText(appDataPath);
                Console.WriteLine(jsonContent); // Or process the JSON content as needed
            }
            else
            {
                Console.WriteLine("File not found in AppDataDirectory.");
            }
        }
    }
}
