using System;
using System.Linq;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Text.RegularExpressions;
using OpenCvSharp;
using TesseractOcrMaui;
using Microsoft.Maui.Storage;
using Tesseract;

namespace VerifyIdentityProject.Helpers.MRZReader
{
    public class MrzReader
    {
        public Command ScanMrzCommand { get; }
        private readonly ITesseract _tesseract;

        public MrzReader(ITesseract tesseract)
        {
            _tesseract = tesseract ?? throw new ArgumentNullException(nameof(tesseract));
            ScanMrzCommand = new Command(async () => await ScanMrz());
            Task.Run(() => EnsureTessDataFileAsync()).Wait(); // Ensure the file is ready
        }

        private async Task EnsureTessDataFileAsync()
        {
            // Define the target directory for tessdata
            string tessDataPath = Path.Combine(FileSystem.CacheDirectory, "tessdata");
            if (!Directory.Exists(tessDataPath))
            {
                Directory.CreateDirectory(tessDataPath);
            }

            // Define the destination path for eng.traineddata
            string trainedDataFilePath = Path.Combine(tessDataPath, "eng.traineddata");

            // Check if the file already exists
            if (!File.Exists(trainedDataFilePath))
            {
                // Copy the file from the app package to the target directory
                using var stream = await FileSystem.OpenAppPackageFileAsync("tessdata/eng.traineddata");
                using var output = File.Create(trainedDataFilePath);
                await stream.CopyToAsync(output);
                Console.WriteLine("eng.traineddata copied to: " + trainedDataFilePath);
            }
            else
            {
                Console.WriteLine("eng.traineddata already exists at: " + trainedDataFilePath);
            }
        }


        public async Task ScanMrz()
        {
            try
            {
                var photo = await MediaPicker.CapturePhotoAsync();
                if (photo == null) return;

                // Save the photo locally and get the file path
                var filePath = Path.Combine(FileSystem.CacheDirectory, photo.FileName);
                using (var stream = await photo.OpenReadAsync())
                using (var fileStream = File.OpenWrite(filePath))
                {
                    await stream.CopyToAsync(fileStream);
                }

                // Read and process MRZ from the image
                var mrzText = await ReadMrzAsync(filePath);
                Console.WriteLine($"Extracted MRZ: {mrzText}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error capturing photo: {ex.Message}");
            }
        }

        private async Task<string> ReadMrzAsync(string imagePath)
        {
            try
            {
                // Define temp image path for Tesseract processing
                string tempImagePath = Path.Combine(FileSystem.CacheDirectory, "temp_image.jpg");

                // Load and preprocess the image
                Mat image = Cv2.ImRead(imagePath, ImreadModes.Grayscale);
                Mat processedImage = PreprocessImage(image);

                // Write the processed image to the temp path
                Cv2.ImWrite(tempImagePath, processedImage);
                Console.WriteLine("Image processed and saved to: " + tempImagePath);

                // Extract text using Tesseract
                string ocrText = await ExtractTextWithTesseract(tempImagePath);

                // Extract MRZ text from OCR results
                return ExtractMrzText(ocrText);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error reading MRZ: {ex.Message}");
                return string.Empty;
            }
        }

        private Mat PreprocessImage(Mat image)
        {
            // Resize the image to half its original size (or any size you prefer)
            Cv2.Resize(image, image, new OpenCvSharp.Size(image.Width / 2, image.Height / 2));

            // Convert the image to grayscale (if it's not already)
            if (image.Channels() > 1)
            {
                Cv2.CvtColor(image, image, ColorConversionCodes.BGR2GRAY);
            }

            // You can adjust the adaptive threshold for better OCR results
            Cv2.AdaptiveThreshold(image, image, 255, AdaptiveThresholdTypes.GaussianC, ThresholdTypes.Binary, 11, 2);

            return image;
        }

        private async Task<string> ExtractTextWithTesseract(string tempImagePath)
        {
            try
            {
                if (_tesseract == null)
                {
                    Console.WriteLine("Tesseract engine is not initialized.");
                    return string.Empty;
                }

                Console.WriteLine("Starting OCR process...");

                // Define the target directory for tessdata
                string tessDataPath = Path.Combine(FileSystem.CacheDirectory, "tessdata");
                if (!Directory.Exists(tessDataPath))
                {
                    Directory.CreateDirectory(tessDataPath);
                }

                // Define the destination path for eng.traineddata
                string trainedDataFilePath = Path.Combine(tessDataPath, "eng.traineddata");

                // Check if the file already exists
                if (!File.Exists(trainedDataFilePath))
                {
                    // Copy the file from the app package to the target directory
                    using var stream = await FileSystem.OpenAppPackageFileAsync("tessdata/eng.traineddata");
                    using var output = File.Create(trainedDataFilePath);
                    await stream.CopyToAsync(output);
                    Console.WriteLine("eng.traineddata copied to: " + trainedDataFilePath);
                }
                else
                {
                    Console.WriteLine("eng.traineddata already exists at: " + trainedDataFilePath);
                }

                Console.WriteLine($"Tessdata path: {tessDataPath}");
                Console.WriteLine($"File exists: {File.Exists(Path.Combine(tessDataPath, "eng.traineddata"))}");

                try
                {
                    Console.WriteLine("Starting OCR process...");

                    var result = await _tesseract.RecognizeTextAsync(tempImagePath);
                    Console.WriteLine("OCR process completed.");

                    if (result.RecognisedText == null || string.IsNullOrWhiteSpace(result.RecognisedText))
                    {
                        Console.WriteLine("OCR result is empty.");
                        return string.Empty;
                    }

                    Console.WriteLine($"OCR Result: {result.RecognisedText}");
                    return result.RecognisedText;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error during OCR processing: {ex.Message}");
                    return string.Empty;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error during OCR processing: {ex.Message}");
                return string.Empty;
            }
        }

        private string ExtractMrzText(string ocrText)
        {
            // Regex pattern for MRZ lines (44 alphanumeric characters, may include '<')
            string pattern = @"^[A-Z0-9<]{10,}$";


            // Split the OCR output into lines and filter valid MRZ lines
            var mrzLines = ocrText
                .Split('\n', StringSplitOptions.RemoveEmptyEntries)
                .Where(line => Regex.IsMatch(line.Trim(), pattern))
                .ToList();

            // Combine valid MRZ lines
            return string.Join("\n", mrzLines);
        }
    }
}
