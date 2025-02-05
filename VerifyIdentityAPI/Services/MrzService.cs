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

                // Crop the bottom half where MRZ is most likely to be located
                //Mat croppedImage = CropBottomHalf(image);

                //// Optionally, save the cropped image for debugging:
                //string croppedPath = Path.Combine(Path.GetTempPath(), "cropped_image.png");
                //Cv2.ImWrite(croppedPath, croppedImage);
                //Console.WriteLine($"Cropped image saved at: {croppedPath}");

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

            // 9. Additional Otsu's Thresholding for better binarization

            Cv2.AdaptiveThreshold(image, image, 255, AdaptiveThresholdTypes.GaussianC, ThresholdTypes.Binary,65, 30);
            Cv2.ImWrite(processedImagePath, image);
            //Cv2.Threshold(image, image, 0, 255, ThresholdTypes.Binary | ThresholdTypes.Otsu);
            //Cv2.ImWrite(processedImagePath, image);
            //Cv2.Threshold(image, image, 0, 255, ThresholdTypes.Binary | ThresholdTypes.Otsu);
            //Cv2.ImWrite(processedImagePath, image);


            //// 2. Resize the image to improve accuracy
            //Cv2.Resize(image, image, new OpenCvSharp.Size(image.Width * 2, image.Height * 2));

            //Cv2.ImWrite(processedImagePath, image);
            //// 3. Histogram Equalization
            //Cv2.EqualizeHist(image, image);
            //Cv2.ImWrite(processedImagePath, image);
            //// 4. CLAHE contrast enhancement
            //using var clahe = Cv2.CreateCLAHE(clipLimit: 3.0, tileGridSize: new OpenCvSharp.Size(8, 8));
            //clahe.Apply(image, image);
            //Cv2.ImWrite(processedImagePath, image);
            //// 5. Gaussian Blurring to reduce noise
            //Cv2.GaussianBlur(image, image, new OpenCvSharp.Size(5, 5), 0);
            //Cv2.ImWrite(processedImagePath, image);
            //// 7. Sharpening (multiple steps)
            //Mat sharpened = new Mat();
            //Cv2.AddWeighted(image, 1.5, image, -0.5, 0, sharpened);
            //image = sharpened;
            //Cv2.ImWrite(processedImagePath, image);
            // 8. Adaptive Thresholding
            //Cv2.AdaptiveThreshold(image, image, 255, AdaptiveThresholdTypes.GaussianC, ThresholdTypes.Binary, 11, 2);

            // 10. Contrast Stretching
            Cv2.Normalize(image, image, 0, 255, NormTypes.MinMax);
            Cv2.ImWrite(processedImagePath, image);
            // 11. Morphological operations to enhance text regions
            Mat morphResult = new Mat();
            var kernel = Cv2.GetStructuringElement(MorphShapes.Rect, new OpenCvSharp.Size(25, 7));
            Cv2.MorphologyEx(image, morphResult, MorphTypes.Close, kernel, iterations: 0);  // Closing to connect text regions
            Cv2.MorphologyEx(morphResult, morphResult, MorphTypes.Open, kernel, iterations: 0);  // Opening to remove small noise
            Cv2.ImWrite(processedImagePath, morphResult);
            // 12. Erosion to remove small white noise
            Cv2.Erode(morphResult, morphResult, kernel, iterations: 2);
            Cv2.ImWrite(processedImagePath, morphResult);
            // 13. Dilation to enhance black text and make it bolder
            Cv2.Dilate(morphResult, morphResult, kernel, iterations: 2);
            Cv2.ImWrite(processedImagePath, image);
            // 14. Additional noise reduction using median blur
            Cv2.MedianBlur(morphResult, morphResult, 1);
            Cv2.ImWrite(processedImagePath, morphResult);

            // Optional: Canny Edge Detection
            Cv2.Canny(morphResult, morphResult, 50, 150);
            // Find contours in the binary image
            Cv2.ImWrite(processedImagePath, morphResult);
            // Find contours in the binary image
            OpenCvSharp.Point[][] contours;
            HierarchyIndex[] hierarchy;
            Cv2.FindContours(morphResult, out contours, out hierarchy, RetrievalModes.List, ContourApproximationModes.ApproxSimple);

            // Identify the MRZ region based on aspect ratio and size
            OpenCvSharp.Rect mrzRect = new OpenCvSharp.Rect();
            double maxArea = 0;

            List<OpenCvSharp.Rect> candidateRects = new List<OpenCvSharp.Rect>();
            double imageArea = image.Width * image.Height;

            // Iterate through contours to filter potential MRZ candidates
            foreach (var contour in contours)
            {
                var rect = Cv2.BoundingRect(contour);
                double aspectRatio = (double)rect.Width / rect.Height;
                double area = rect.Width * rect.Height;

                // Heuristics for detecting MRZ
                if (aspectRatio > 2 && aspectRatio < 15 &&  // Aspect ratio range
                    area > imageArea * 0.05              // At least 1% of the image area
                    ) // Minimum dimension constraint            // Focus on lower half of the image
                {
                    candidateRects.Add(rect);

                    // Debug visualization
                    Cv2.Rectangle(image, rect, new Scalar(0, 255, 0), 2);
                }
            }

            // Iterate through candidate rectangles and check for valid MRZ text
            foreach (var rect in candidateRects)
            {
                // Expand the detected rectangle dynamically
                int verticalPadding = (int)(rect.Height * 0.5);
                int horizontalPadding = (int)(rect.Width * 0.3);

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

            // Checks if the text contains the MRZ line format
            return text.Contains("P<");
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

