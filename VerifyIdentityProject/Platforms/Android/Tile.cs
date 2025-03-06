using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Collections.Generic;

namespace VerifyIdentityProject.Platforms.Android
{
    public class Tile
    {
        // Tile indices in the grid
        public int TileIndexX { get; set; }
        public int TileIndexY { get; set; }

        // Boundaries of the tile in the reference grid
        public uint X0 { get; set; }  // Left coordinate
        public uint Y0 { get; set; }  // Top coordinate
        public uint X1 { get; set; }  // Right coordinate (exclusive)
        public uint Y1 { get; set; }  // Bottom coordinate (exclusive)

        public override string ToString()
        {
            return $"Tile[{TileIndexX},{TileIndexY}]: ({X0},{Y0}) to ({X1},{Y1})";
        }
    }

    public static class TileParser
    {
        /// <summary>
        /// Computes tile boundaries based on the SIZ marker parameters.
        /// </summary>
        /// <param name="siz">The SIZ marker with image and tile parameters.</param>
        /// <returns>A list of Tile objects with computed boundaries.</returns>
        public static List<Tile> ComputeTiles(SIZMarker siz)
        {
            List<Tile> tiles = new List<Tile>();

            // Compute the number of tiles horizontally and vertically using ceiling:
            int numTilesX = (int)Math.Ceiling((siz.Xsiz - siz.XTOsiz) / (double)siz.XTsiz);
            int numTilesY = (int)Math.Ceiling((siz.Ysiz - siz.YTOsiz) / (double)siz.YTsiz);

            for (int j = 0; j < numTilesY; j++)
            {
                for (int i = 0; i < numTilesX; i++)
                {
                    // Compute the tile's top-left coordinate:
                    uint tileX0 = siz.XTOsiz + (uint)(i * siz.XTsiz);
                    uint tileY0 = siz.YTOsiz + (uint)(j * siz.YTsiz);

                    // Compute the tile's bottom-right coordinate, ensuring we don't exceed the reference grid.
                    uint tileX1 = Math.Min(siz.XTOsiz + (uint)((i + 1) * siz.XTsiz), siz.Xsiz);
                    uint tileY1 = Math.Min(siz.YTOsiz + (uint)((j + 1) * siz.YTsiz), siz.Ysiz);

                    tiles.Add(new Tile()
                    {
                        TileIndexX = i,
                        TileIndexY = j,
                        X0 = tileX0,
                        Y0 = tileY0,
                        X1 = tileX1,
                        Y1 = tileY1
                    });
                }
            }

            return tiles;
        }
    }

}
