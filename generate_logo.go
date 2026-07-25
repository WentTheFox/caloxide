//go:build ignore
package main

import (
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math"
	"math/rand"
	"os"
	"time"
)

func main() {
	rand.Seed(time.Now().UnixNano())
	
	width, height := 1280, 640
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	
	bgColor := color.RGBA{40, 42, 54, 255}
	gridColor := color.RGBA{68, 71, 90, 255}
	fillColor := color.RGBA{88, 101, 116, 255}
	
	accentColors := []color.RGBA{
		{255, 107, 107, 255},
		{107, 255, 141, 255},
		{107, 170, 255, 255},
		{255, 212, 107, 255},
		{255, 107, 212, 255},
		{170, 107, 255, 255},
		{107, 255, 212, 255},
	}
	
	draw.Draw(img, img.Bounds(), &image.Uniform{bgColor}, image.Point{}, draw.Src)
	
	// Floating confetti dots
	for i := 0; i < 150; i++ {
		x := rand.Intn(width)
		y := rand.Intn(height)
		c := accentColors[rand.Intn(len(accentColors))]
		c.A = uint8(rand.Intn(128) + 64)
		img.Set(x, y, c)
		if rand.Intn(2) == 0 {
			img.Set(x+1, y, c)
			img.Set(x, y+1, c)
		}
	}
	
	// CALENDAR ICON
	cellSize := 48
	gridCols, gridRows := 7, 5
	gridWidth := gridCols * cellSize
	gridHeight := gridRows * cellSize
	gridX := (width - gridWidth) / 2
	gridY := (height - gridHeight) / 2
	
	for row := 0; row < gridRows; row++ {
		for col := 0; col < gridCols; col++ {
			x := gridX + col*cellSize
			y := gridY + row*cellSize
			cellFill := fillColor
			if row == 0 {
				cellFill = color.RGBA{uint8(int(fillColor.R) + 10), uint8(int(fillColor.G) + 10), uint8(int(fillColor.B) + 10), 255}
			}
			for i := 2; i < cellSize-2; i++ {
				for j := 2; j < cellSize-2; j++ {
					img.Set(x+i, y+j, cellFill)
				}
			}
			img.Set(x+1, y+1, cellFill)
			img.Set(x+cellSize-2, y+1, cellFill)
			img.Set(x+1, y+cellSize-2, cellFill)
			img.Set(x+cellSize-2, y+cellSize-2, cellFill)
			
			for i := 1; i < cellSize-1; i++ {
				img.Set(x+i, y, gridColor)
				img.Set(x+i, y+cellSize-1, gridColor)
			}
			for i := 2; i < cellSize-2; i++ {
				img.Set(x, y+i, gridColor)
				img.Set(x+cellSize-1, y+i, gridColor)
			}
			img.Set(x+1, y, gridColor)
			img.Set(x+cellSize-2, y, gridColor)
			img.Set(x+1, y+cellSize-1, gridColor)
			img.Set(x+cellSize-2, y+cellSize-1, gridColor)
		}
	}
	
	eventCells := []struct{ col, row, w, h int }{
		{2, 1, 1, 1}, {4, 1, 1, 1}, {1, 2, 1, 2}, {5, 3, 1, 1},
		{3, 2, 1, 1}, {0, 1, 1, 1}, {6, 2, 1, 1}, {2, 3, 1, 1},
		{4, 0, 1, 1}, {1, 4, 2, 1},
	}
	for idx, ec := range eventCells {
		x := gridX + ec.col*cellSize + 4
		y := gridY + ec.row*cellSize + 4
		w, h := ec.w*(cellSize-8), ec.h*(cellSize-8)
		c := accentColors[idx%len(accentColors)]
		for i := 0; i < w; i++ {
			for j := 0; j < h; j++ {
				if x+i < width && y+j < height {
					img.Set(x+i, y+j, c)
				}
			}
		}
		for i := 0; i < w; i++ {
			if x+i+1 < width && y+1 < height {
				img.Set(x+i+1, y+1, color.RGBA{uint8(int(c.R) * 8 / 10), uint8(int(c.G) * 8 / 10), uint8(int(c.B) * 8 / 10), 255})
			}
		}
	}
	
	// Smiling sun
	drawSmileySun(img, 80, 80, 30, color.RGBA{255, 215, 0, 255})
	
	// Whimsical cloud
	drawCloud(img, 1100, 60, 40, accentColors[1])
	
	// Lightning bolts
	drawLightning(img, 200, 500, 25, accentColors[2])
	drawLightning(img, 1080, 500, 25, accentColors[5])
	
	// Floating shapes
	drawTriangle(img, 950, 450, 20, accentColors[3])
	drawHexagon(img, 100, 520, 18, accentColors[4])
	
	// Bridge cable
	drawBridgeCable(img, gridX+gridWidth+40, gridY+gridHeight/2, gridX-40, gridY+gridHeight/2, accentColors[0])
	
	outFile, err := os.Create("protoxide-logo.png")
	if err != nil {
		panic(err)
	}
	defer outFile.Close()
	
	if err := png.Encode(outFile, img); err != nil {
		panic(err)
	}
	
	println("Logo generated: protoxide-logo.png")
}

func drawSmileySun(img *image.RGBA, cx, cy, radius int, c color.Color) {
	for angle := 0; angle < 360; angle += 30 {
		rad := float64(angle) * math.Pi / 180.0
		outerRadius := radius * 15 / 10
		for r := radius; r <= outerRadius; r += 2 {
			x := cx + int(float64(r)*math.Cos(rad))
			y := cy + int(float64(r)*math.Sin(rad))
			if x >= 0 && x < 1280 && y >= 0 && y < 640 {
				img.Set(x, y, c)
			}
		}
	}
	for angle := 0; angle < 360; angle += 5 {
		rad := float64(angle) * math.Pi / 180.0
		for r := 0; r < radius; r++ {
			x := cx + int(float64(r)*math.Cos(rad))
			y := cy + int(float64(r)*math.Sin(rad))
			if x >= 0 && x < 1280 && y >= 0 && y < 640 {
				img.Set(x, y, c)
			}
		}
	}
	img.Set(cx-8, cy-5, color.RGBA{0, 0, 0, 255})
	img.Set(cx+8, cy-5, color.RGBA{0, 0, 0, 255})
	img.Set(cx-7, cy-5, color.RGBA{0, 0, 0, 255})
	img.Set(cx+7, cy-5, color.RGBA{0, 0, 0, 255})
	for angle := -45; angle <= 45; angle += 5 {
		rad := float64(angle) * math.Pi / 180.0
		x := cx + int(float64(radius-3)*math.Cos(rad))
		y := cy + 5 + int(float64(radius-3)*math.Sin(rad))
		if x >= 0 && x < 1280 && y >= 0 && y < 640 {
			img.Set(x, y, color.RGBA{0, 0, 0, 255})
		}
	}
}

func drawCloud(img *image.RGBA, cx, cy, size int, c color.Color) {
	drawCircle(img, cx, cy, size, c)
	drawCircle(img, cx+size, cy, size, c)
	drawCircle(img, cx+size/2, cy+size/2, size, c)
	drawCircle(img, cx+size*3/2, cy+size/2, size, c)
}

func drawCircle(img *image.RGBA, cx, cy, radius int, c color.Color) {
	for angle := 0; angle < 360; angle += 5 {
		rad := float64(angle) * math.Pi / 180.0
		for r := -radius; r <= radius; r++ {
			d := math.Sqrt(float64(r*r) + float64(radius*radius) - 2*float64(r)*float64(radius)*math.Cos(rad))
			if d <= float64(radius) {
				x := cx + int(float64(r)*math.Cos(rad))
				y := cy + int(float64(r)*math.Sin(rad))
				if x >= 0 && x < 1280 && y >= 0 && y < 640 {
					img.Set(x, y, c)
				}
			}
		}
	}
}

func drawLightning(img *image.RGBA, cx, cy, size int, c color.Color) {
	points := []struct{ dx, dy int }{
		{0, -size}, {size/2, -size/2}, {0, 0}, {-size/2, size/2}, {0, size},
	}
	for _, p := range points {
		x := cx + p.dx
		y := cy + p.dy
		if x >= 0 && x < 1280 && y >= 0 && y < 640 {
			img.Set(x, y, c)
			img.Set(x+1, y, c)
			img.Set(x, y+1, c)
		}
	}
	for i := 0; i < len(points)-1; i++ {
		p1 := points[i]
		p2 := points[i+1]
		x1, y1 := cx+p1.dx, cy+p1.dy
		x2, y2 := cx+p2.dx, cy+p2.dy
		steps := 10
		for s := 0; s <= steps; s++ {
			x := x1 + (x2-x1)*s/steps
			y := y1 + (y2-y1)*s/steps
			if x >= 0 && x < 1280 && y >= 0 && y < 640 {
				img.Set(x, y, c)
				img.Set(x+1, y, c)
			}
		}
	}
}

func drawTriangle(img *image.RGBA, cx, cy, size int, c color.Color) {
	height := int(float64(size) * math.Sqrt(3) / 2)
	points := []struct{ x, y int }{
		{cx, cy - height},
		{cx - size, cy + height},
		{cx + size, cy + height},
	}
	for i := 0; i < 3; i++ {
		p1 := points[i]
		p2 := points[(i+1)%3]
		for s := 0; s <= 10; s++ {
			x := p1.x + (p2.x-p1.x)*s/10
			y := p1.y + (p2.y-p1.y)*s/10
			if x >= 0 && x < 1280 && y >= 0 && y < 640 {
				img.Set(x, y, c)
			}
		}
	}
}

func drawHexagon(img *image.RGBA, cx, cy, size int, c color.Color) {
	for angle := 0; angle < 360; angle += 60 {
		rad := float64(angle) * math.Pi / 180.0
		for r := 0; r < size; r++ {
			x := cx + int(float64(r)*math.Cos(rad))
			y := cy + int(float64(r)*math.Sin(rad))
			if x >= 0 && x < 1280 && y >= 0 && y < 640 {
				img.Set(x, y, c)
			}
		}
	}
}

func drawBridgeCable(img *image.RGBA, x1, y1, x2, y2 int, c color.Color) {
	steps := 40
	self := rand.Float64() * 10
	for s := 0; s <= steps; s++ {
		t := float64(s) / float64(steps)
		x := x1 + int(float64(x2-x1)*t)
		y := y1 + int(float64(y2-y1)*t) + int(self*math.Sin(t*math.Pi*2))
		for dy := -2; dy <= 2; dy++ {
			if x >= 0 && x < 1280 && y+dy >= 0 && y+dy < 640 {
				img.Set(x, y+dy, c)
			}
		}
	}
	drawCircle(img, x1, y1, 8, c)
	drawCircle(img, x2, y2, 8, c)
}
