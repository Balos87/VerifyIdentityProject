using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VerifyIdentityProject.Helpers.MRZReader
{
    public class MrzGuideDrawable : IDrawable
    {
        public void Draw(ICanvas canvas, RectF dirtyRect)
        {
            // Set semi-transparent background for the MRZ guide
            canvas.FillColor = new Color(0, 0, 0, 0.5f);
            canvas.FillRectangle(dirtyRect);

            // Highlight the MRZ region with a transparent rectangle
            var guideHeight = dirtyRect.Height * 0.2f; // 20% height for the MRZ region
            var guideRect = new RectF(dirtyRect.X, dirtyRect.Bottom - guideHeight, dirtyRect.Width, guideHeight);

            // Draw MRZ guide
            canvas.FillColor = Colors.Transparent;
            canvas.StrokeColor = Colors.White;
            canvas.StrokeSize = 2;
            canvas.DrawRectangle(guideRect);
        }
    }

}
