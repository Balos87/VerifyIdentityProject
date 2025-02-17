using System.Drawing;
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

        public MrzService(TesseractEngine tesseractEngine)
        {
            _tesseractEngine = tesseractEngine;
        }

        public async Task<string> ExtractMrzAsync(string imagePath)
        {
            return await Task.Run(() =>
            {
                // Load and preprocess the image
                Mat image = Cv2.ImRead(imagePath);
                if (image.Empty())
                {
                    Console.WriteLine("Failed to load image.");
                    throw new Exception("Image loading failed.");
                }


                // Preprocess the cropped MRZ region
                Mat processedImage = CropToMrzRegion(image);

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
                        ocrResult = page.GetText().Replace(" ", "");
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
            // Save for debugging
            string processedImagePath = Path.Combine(Path.GetTempPath(), "cropped_image.png");
            string originalImagePath = Path.Combine(Path.GetTempPath(), "default_image.png");
            Cv2.ImWrite(originalImagePath, image);
            // 1. Convert to grayscale if not already
            if (image.Channels() != 1)
                Cv2.CvtColor(image, image, ColorConversionCodes.BGR2GRAY);

            // 2. Additional Otsu's Thresholding for better binarization
            Cv2.AdaptiveThreshold(image, image, 255, AdaptiveThresholdTypes.GaussianC, ThresholdTypes.Binary, 65, 30);
            Cv2.ImWrite(processedImagePath, image);

            // 3. Contrast Stretching
            Cv2.Normalize(image, image, 0, 255, NormTypes.MinMax);
            Cv2.ImWrite(processedImagePath, image);

            // 4. Morphological operations to enhance text regions
            Mat morphResult = new Mat();
            var kernel = Cv2.GetStructuringElement(MorphShapes.Rect, new OpenCvSharp.Size(25, 7));
            Cv2.MorphologyEx(image, morphResult, MorphTypes.Close, kernel, iterations: 0);  // Closing to connect text regions
            Cv2.MorphologyEx(morphResult, morphResult, MorphTypes.Open, kernel, iterations: 0);  // Opening to remove small noise
            Cv2.ImWrite(processedImagePath, morphResult);

            // 5. Erosion to remove small white noise
            Cv2.Erode(morphResult, morphResult, kernel, iterations: 2);
            Cv2.ImWrite(processedImagePath, morphResult);

            // 6. Dilation to enhance black text and make it bolder
            Cv2.Dilate(morphResult, morphResult, kernel, iterations: 2);
            Cv2.ImWrite(processedImagePath, image);

            // 7. Additional noise reduction using median blur
            Cv2.MedianBlur(morphResult, morphResult, 1);
            Cv2.ImWrite(processedImagePath, morphResult);

            // Canny Edge Detection
            Cv2.Canny(morphResult, morphResult, 50, 150);
            Cv2.ImWrite(processedImagePath, morphResult);
            // Find contours in the binary image
            OpenCvSharp.Point[][] contours;
            HierarchyIndex[] hierarchy;
            Cv2.FindContours(morphResult, out contours, out hierarchy, RetrievalModes.External, ContourApproximationModes.ApproxSimple);

            List<OpenCvSharp.Rect> candidateRects = new List<OpenCvSharp.Rect>();
            double imageArea = image.Width * image.Height;

            // Iterate through contours to filter potential MRZ candidates
            foreach (var contour in contours)
            {
                var rect = Cv2.BoundingRect(contour);
                double aspectRatio = (double)rect.Width / rect.Height;
                double area = rect.Width * rect.Height;

                // Heuristics for detecting MRZ
                if (aspectRatio > 20 && aspectRatio < 55)
                {
                    candidateRects.Add(rect);

                    // Debug visualization
                    //Cv2.Rectangle(image, rect, new Scalar(0, 255, 0), 2);
                }
            }

            // Iterate through candidate rectangles and check for valid MRZ text
            foreach (var rect in candidateRects)
            {
                // Expand the detected rectangle dynamically
                int verticalPadding = (int)(rect.Height * 0.4);
                int horizontalPadding = (int)(rect.Width * 0.1);

                int newX = Math.Max(0, rect.X - horizontalPadding);
                int newY = Math.Max(0, rect.Y - verticalPadding);
                int newWidth = Math.Min(image.Width - newX, rect.Width + 2 * horizontalPadding);
                int newHeight = Math.Min(image.Height - newY, rect.Height + 2 * verticalPadding);

                OpenCvSharp.Rect expandedRect = new OpenCvSharp.Rect(newX, newY, newWidth, newHeight);

                // Crop the detected and expanded region
                Mat croppedMrz = new Mat(image, expandedRect);

                // Save the cropped MRZ candidate for debugging
                string debugImagePath = Path.Combine(Path.GetTempPath(), $"mrz_candidate.png");
                Cv2.ImWrite(debugImagePath, croppedMrz);

                // Check if the cropped region contains MRZ content
                if (ContainsCharacters(croppedMrz))
                {
                    Console.WriteLine("MRZ detected!");
                    return croppedMrz;
                }
            }

            Console.WriteLine("No valid MRZ detected.");
            return image;
        }

        private bool ContainsCharacters(Mat image)
        {

            // Convert OpenCV Mat to Tesseract-compatible bitmap
            Bitmap bitmap = OpenCvSharp.Extensions.BitmapConverter.ToBitmap(image);

            _tesseractEngine.SetVariable("tessedit_char_whitelist", "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789<");
            using var page = _tesseractEngine.Process(bitmap, PageSegMode.AutoOsd);
            string text = page.GetText().Replace("\n", "").Replace(" ", ""); // Remove whitespace and newlines

            if(!text.Contains("P<") && text.Length == 44)
            {
                return true;
            }
            else
            {
                return false;
            }
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

            // Extract characters for BAC: 1-10, 13-19 and 21-27. 
            string bacRelevantPart = lastLine.Substring(0, 10) + lastLine.Substring(13, 7) + lastLine.Substring(21, 7);

            if(bacRelevantPart.Length != 24)
            {
                return string.Empty;
            }
            if (bacRelevantPart.Contains("P<")) 
            {
                return string.Empty;
            }
            return bacRelevantPart;
        }
    }
}

