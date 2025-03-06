using System;
using System.Collections.Generic;

namespace VerifyIdentityProject.Platforms.Android
{
    /// <summary>
    /// Represents one resolution level in the image.
    /// </summary>
    public class ResolutionLevel
    {
        // Resolution level index (0 = lowest resolution, D = highest resolution)
        public int Level { get; set; }
        // Computed width and height at this resolution level.
        public int Width { get; set; }
        public int Height { get; set; }

        public override string ToString()
        {
            return $"Level {Level}: {Width}x{Height}";
        }
    }

    public static class ResolutionLevelCalculator
    {
        /// <summary>
        /// Computes the resolution levels for a JPEG2000 image.
        /// </summary>
        /// <param name="siz">The SIZ marker containing full image dimensions.</param>
        /// <param name="decompositionLevels">The number of wavelet decomposition levels (D) from the COD marker (SGcod).</param>
        /// <returns>A list of resolution levels (from 0 to D), where each level contains its computed width and height.</returns>
        public static List<ResolutionLevel> ComputeResolutionLevels(SIZMarker siz, int decompositionLevels)
        {
            // Total resolution levels = decompositionLevels + 1.
            int totalLevels = decompositionLevels + 1;
            List<ResolutionLevel> levels = new List<ResolutionLevel>();

            // The full image dimensions (from the SIZ marker, reference grid dimensions)
            int fullWidth = (int)siz.Xsiz;
            int fullHeight = (int)siz.Ysiz;

            for (int r = 0; r < totalLevels; r++)
            {
                // The reduction factor at resolution level r is 2^(decompositionLevels - r).
                int factor = (int)Math.Pow(2, decompositionLevels - r);
                // Use ceiling to account for rounding.
                int levelWidth = (int)Math.Ceiling(fullWidth / (double)factor);
                int levelHeight = (int)Math.Ceiling(fullHeight / (double)factor);

                levels.Add(new ResolutionLevel
                {
                    Level = r,
                    Width = levelWidth,
                    Height = levelHeight
                });
            }
            return levels;
        }
    }
}
