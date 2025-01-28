using System;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Threading.Tasks;
using Microsoft.Maui.Media;
using OpenCvSharp;
#if ANDROID
using Android.OS;
using Android.Content.PM; // Add this import
#endif

namespace VerifyIdentityProject.Helpers.MRZReader
{
    public class MrzReader
    {
        private readonly HttpClient _httpClient;

        public MrzReader()
        {
            _httpClient = new HttpClient
            {
                BaseAddress = new Uri("http://192.168.50.26:5000/") // Local API URL
            };
        }

        public async Task ScanAndExtractMrzAsync()
        {
            try
            {
                // Capture photo using the device's camera
                var photo = await MediaPicker.CapturePhotoAsync();
                if (photo == null)
                {
                    Console.WriteLine("No photo captured.");
                    return;
                }

                // Save the photo locally
                var filePath = Path.Combine(FileSystem.CacheDirectory, photo.FileName);
                using (var stream = await photo.OpenReadAsync())
                using (var fileStream = File.OpenWrite(filePath))
                {
                    await stream.CopyToAsync(fileStream);
                }

                // Detect and crop the MRZ region
                var mrzRegionPath = await DetectMrzRegionAsync(filePath);
                if (mrzRegionPath == null)
                {
                    Console.WriteLine("No MRZ region detected in the image.");
                    return;
                }

                // Send the cropped MRZ region to the API
                var mrzText = await ExtractMrzFromApiAsync(filePath);

                if (string.IsNullOrEmpty(mrzText))
                {
                    Console.WriteLine("No MRZ detected in the image.");
                }
                else
                {
                    Console.WriteLine($"Extracted MRZ: {mrzText}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error during MRZ scan: {ex.Message}");
            }
        }

        private async Task<string> DetectMrzRegionAsync(string imagePath)
        {
            try
            {
                using (var originalImage = Mat.FromImageData(await File.ReadAllBytesAsync(imagePath)))
                {
                    // Convert to grayscale
                    using (var grayImage = new Mat())
                    {
                        Cv2.CvtColor(originalImage, grayImage, ColorConversionCodes.BGR2GRAY);

                        // Perform edge detection
                        using (var edges = new Mat())
                        {
                            Cv2.Canny(grayImage, edges, 50, 150);

                            // Debug: Save the edge-detected image
                            var debugEdgesPath = Path.Combine(FileSystem.CacheDirectory, "debug_edges.jpg");
                            edges.SaveImage(debugEdgesPath);
                            Console.WriteLine($"Edge-detected image saved to: {debugEdgesPath}");

                            // Find contours
                            var contours = Cv2.FindContoursAsArray(edges, RetrievalModes.External, ContourApproximationModes.ApproxSimple);
                            Console.WriteLine($"Number of contours detected: {contours.Length}");

                            OpenCvSharp.Rect? largestMrzRect = null;

                            // Iterate through contours
                            foreach (var contour in contours)
                            {
                                var rect = Cv2.BoundingRect(contour);

                                // Expand the bounding rectangle
                                var expandedRect = new OpenCvSharp.Rect(
                                    0,
                                    Math.Max(rect.Y - 50, 0), // Expand up
                                    originalImage.Width,
                                    Math.Min(rect.Height + 100, originalImage.Height - rect.Y) // Expand height
                                );

                                // Log dimensions and aspect ratio
                                double aspectRatio = (double)expandedRect.Width / expandedRect.Height;
                                Console.WriteLine($"Contour: X={expandedRect.X}, Y={expandedRect.Y}, Width={expandedRect.Width}, Height={expandedRect.Height}, AspectRatio={aspectRatio}");

                                // Filter MRZ-like dimensions
                                if (aspectRatio > 2.0 && aspectRatio < 12.0 && expandedRect.Height > 30)
                                {
                                    Console.WriteLine("Potential MRZ region detected!");

                                    // Use the largest detected rectangle
                                    if (largestMrzRect == null || expandedRect.Width * expandedRect.Height > largestMrzRect.Value.Width * largestMrzRect.Value.Height)
                                    {
                                        largestMrzRect = expandedRect;
                                    }
                                }
                            }

                            if (largestMrzRect != null)
                            {
                                Console.WriteLine("Final MRZ region detected. Saving...");

                                // Crop and save the expanded MRZ region
                                using (var mrzRegion = new Mat(originalImage, largestMrzRect.Value))
                                {
#if ANDROID
                                    // Define the Downloads folder path
                                    var downloadsPath = Path.Combine(Android.OS.Environment.GetExternalStoragePublicDirectory(Android.OS.Environment.DirectoryDownloads).AbsolutePath, "MRZImages");
                                    Directory.CreateDirectory(downloadsPath); // Ensure the directory exists

                                    // Define cropped image path
                                    var croppedPath = Path.Combine(downloadsPath, "mrz_region.jpg");
#else
                            var croppedPath = Path.Combine(FileSystem.CacheDirectory, "mrz_region.jpg");
#endif

                                    // Save cropped image
                                    mrzRegion.SaveImage(croppedPath);
                                    Console.WriteLine($"MRZ region saved to: {croppedPath}");

                                    return croppedPath; // Return the path to the cropped image
                                }
                            }

                            // If no MRZ is detected, save the full image
                            Console.WriteLine("No MRZ region detected. Saving the full image.");
#if ANDROID
                            var fullImagePath = Path.Combine(Android.OS.Environment.GetExternalStoragePublicDirectory(Android.OS.Environment.DirectoryDownloads).AbsolutePath, "MRZImages", "full_image.jpg");
#else
                    var fullImagePath = Path.Combine(FileSystem.CacheDirectory, "full_image.jpg");
#endif
                            Directory.CreateDirectory(Path.GetDirectoryName(fullImagePath));
                            originalImage.SaveImage(fullImagePath);
                            Console.WriteLine($"Full image saved to: {fullImagePath}");
                            return fullImagePath;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error detecting MRZ: {ex.Message}");
                return null;
            }
        }

        private async Task<string> ExtractMrzFromApiAsync(string imagePath)
        {
            try
            {
                Console.WriteLine("Sending image to API...");

                using var fileStream = File.OpenRead(imagePath);
                using var content = new MultipartFormDataContent();

                var fileContent = new StreamContent(fileStream)
                {
                    Headers =
                    {
                        ContentType = new MediaTypeHeaderValue("image/jpeg")
                    }
                };

                content.Add(fileContent, "file", Path.GetFileName(imagePath));

                var response = await _httpClient.PostAsync("api/mrz/extract", content);

                var responseString = await response.Content.ReadAsStringAsync();
                if (response.IsSuccessStatusCode)
                {
                    Console.WriteLine($"MRZ Extracted: {responseString}");
                    return responseString;
                }
                else
                {
                    Console.WriteLine($"API Error: {response.StatusCode} - {responseString}");
                    return string.Empty;
                }
            }
            catch (HttpRequestException ex)
            {
                Console.WriteLine($"HTTP Request error: {ex.Message}");
                return string.Empty;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Unexpected error: {ex.Message}");
                return string.Empty;
            }
        }
    }
}

