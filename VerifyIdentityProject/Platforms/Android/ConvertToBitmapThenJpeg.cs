using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Android.Graphics;
using Java.Nio;

namespace VerifyIdentityProject.Platforms.Android
{
    public class ConvertToBitmapThenJpeg
    {
        public Bitmap ConvertToBitmap(byte[] pixelData, int width, int height)
        {
            Bitmap bitmap = Bitmap.CreateBitmap(width, height, Bitmap.Config.Argb8888);
            int[] pixels = new int[width * height];

            for (int i = 0; i < pixels.Length; i++)
            {
                int red = pixelData[i * 3];
                int green = pixelData[i * 3 + 1];
                int blue = pixelData[i * 3 + 2];

                pixels[i] = (255 << 24) | (red << 16) | (green << 8) | blue;
            }

            bitmap.SetPixels(pixels, 0, width, 0, 0, width, height);
            return bitmap;
        }

        public Bitmap CreateBitmapFromPixelData(byte[] pixelData, int width, int height)
        {
            Bitmap bitmap = Bitmap.CreateBitmap(width, height, Bitmap.Config.Argb8888);
            IntBuffer buffer = IntBuffer.Wrap(pixelData.Select(b => (int)b).ToArray());
            bitmap.CopyPixelsFromBuffer(buffer);
            return bitmap;
        }

        public void SaveAsJpeg(Bitmap bitmap, string filePath)
        {
            using (FileStream fs = new FileStream(filePath, FileMode.Create))
            {
                bitmap.Compress(Bitmap.CompressFormat.Jpeg, 90, fs);
            }
            Console.WriteLine("JPEG Image Saved!");
        }

        public void SaveBitmapAsJpeg(Bitmap bitmap, string filePath)
        {
            using (FileStream fs = new FileStream(filePath, FileMode.Create))
            {
                bitmap.Compress(Bitmap.CompressFormat.Jpeg, 90, fs);
            }
            Console.WriteLine($"JPEG Image Saved: {filePath}");
        }

    }
}
