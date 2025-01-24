using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using OpenCvSharp;
using Tesseract;

namespace VerifyIdentityAPI.Services
{
    public class MrzService : IMrzService
    {
        private readonly TesseractEngine _tesseractEngine;

        public MrzService()
        {
            // Use the path provided by the NuGet package
            string tessDataPath = Path.Combine(AppContext.BaseDirectory, "tessdata");

            if (!Directory.Exists(tessDataPath))
            {
                Console.WriteLine("Tesseract data directory not found.");
                throw new DirectoryNotFoundException($"Tesseract data directory not found: {tessDataPath}");
            }

            if (!File.Exists(Path.Combine(tessDataPath, "eng.traineddata")))
            {
                Console.WriteLine("eng.traineddata file not found.");
                throw new FileNotFoundException($"eng.traineddata file not found in: {tessDataPath}");
            }

            _tesseractEngine = new TesseractEngine(tessDataPath, "eng", EngineMode.TesseractAndLstm);

            if (!Directory.Exists(tessDataPath))
            {
                Console.WriteLine("Tesseract data directory not found.");
            }
        }

        public async Task<string> ExtractMrzAsync(string imagePath)
        {
            return await Task.Run(() =>
            {
                // Load and preprocess the image
                Mat image = Cv2.ImRead(imagePath, ImreadModes.Grayscale);
                if (image.Empty())
                {
                    Console.WriteLine("Failed to load image.");
                    throw new Exception("Image loading failed.");
                }
                //image = CropToMrzRegion(image);
                Mat processedImage = PreprocessImage(image);

                // Save processed image for debugging
                string processedImagePath = Path.Combine(Path.GetTempPath(), "processed_image.png");
                Cv2.ImWrite(processedImagePath, processedImage);
                Console.WriteLine($"Processed image saved at: {processedImagePath}");

                // Perform OCR
                string ocrResult;
                using (var pix = Pix.LoadFromFile(processedImagePath))
                {
                    _tesseractEngine.SetVariable("tessedit_char_whitelist", "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789<");
                    using (var page = _tesseractEngine.Process(pix, PageSegMode.AutoOsd))
                    {
                        ocrResult = page.GetText();
                        Console.WriteLine($"Raw OCR Output: {ocrResult}");
                    }
                }

                // Extract MRZ lines
                string mrzText = ExtractMrzText(ocrResult);
                Console.WriteLine($"Extracted MRZ Text: {mrzText}");
                return mrzText;
            });
        }

        private Mat CropToMrzRegion(Mat image)
        {
            int height = image.Height;
            int width = image.Width;

            // Adjust cropping parameters to capture more height
            int mrzTop = height * 70 / 100;   // Start cropping slightly higher (70% of height)
            int mrzHeight = height - mrzTop;  // Capture the remaining 30% of the image's height

            // Ensure the cropping rectangle doesn't exceed the image bounds
            mrzHeight = Math.Min(mrzHeight, height - mrzTop);

            OpenCvSharp.Rect mrzRegion = new OpenCvSharp.Rect(0, mrzTop, width, mrzHeight);
            return new Mat(image, mrzRegion);
        }

        private Mat PreprocessImage(Mat image)
        {
            // Focus on the region where the MRZ text should be
            OpenCvSharp.Rect mrzRegion = new OpenCvSharp.Rect(0, image.Height * 70 / 100, image.Width, image.Height * 30 / 100);
            Mat croppedImage = new Mat(image, mrzRegion);

            // Resize the image for better OCR accuracy
            Cv2.Resize(croppedImage, croppedImage, new OpenCvSharp.Size(croppedImage.Width * 1.5, croppedImage.Height * 1.5));

            // Convert to grayscale (if not already)
            if (croppedImage.Channels() != 1)
            {
                Cv2.CvtColor(croppedImage, croppedImage, ColorConversionCodes.BGR2GRAY);
            }

            // Apply simple thresholding for binarization
            Mat thresholdedImage = new Mat();
            Cv2.Threshold(croppedImage, thresholdedImage, 128, 255, ThresholdTypes.BinaryInv);

            // Perform a single morphological operation (Dilation)
            Mat processedImage = new Mat();
            Mat kernel = Cv2.GetStructuringElement(MorphShapes.Rect, new OpenCvSharp.Size(2, 2));
            Cv2.Dilate(thresholdedImage, processedImage, kernel, iterations: 1);

            // Invert the colors so that the text is black and the background is white
            Cv2.BitwiseNot(processedImage, processedImage);

            return processedImage;
        }

        private string ExtractMrzText(string ocrText)
        {
            string pattern = @"^[A-Z0-9<]{44}$"; // MRZ lines are exactly 44 characters
            var mrzLines = ocrText
                .Split('\n', StringSplitOptions.RemoveEmptyEntries)
                .Select(line => line.Trim())
                .Where(line => Regex.IsMatch(line, pattern))
                .ToList();

            // If no valid MRZ lines are found, return an empty string
            if (mrzLines.Count == 0)
                return string.Empty;

            // Get the last MRZ line (assuming it's the second line of the MRZ)
            string lastLine = mrzLines.Last();

            // Extract characters for BAC: 1-10 and 14-30
            string bacRelevantPart = lastLine.Substring(0, 10) + lastLine.Substring(13, 16);

            return bacRelevantPart;
        }
    }
}

