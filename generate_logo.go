//go:build ignore
package main

import (
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math"
	"os"
)

func main() {
	width, height := 512, 512
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	
	// Proton-like color palette
	bgColor := color.RGBA{26, 26, 46, 255}
	gridColor := color.RGBA{55, 71, 79, 255}
	fillColor := color.RGBA{74, 108, 134, 255}
	accentColor := color.RGBA{0, 200, 255, 255}
	
	draw.Draw(img, img.Bounds(), &image.Uniform{bgColor}, image.Point{}, draw.Src)
	
	// CALENDAR ICON - centered, larger
	cellSize := 36
	gridCols, gridRows := 7, 6
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
				cellFill = color.RGBA{60, 80, 95, 255}
			}
			for i := 1; i < cellSize-1; i++ {
				for j := 1; j < cellSize-1; j++ {
					img.Set(x+i, y+j, cellFill)
				}
			}
			for i := 0; i < cellSize; i++ {
				img.Set(x+i, y, gridColor)
				img.Set(x+i, y+cellSize-1, gridColor)
				img.Set(x, y+i, gridColor)
				img.Set(x+cellSize-1, y+i, gridColor)
			}
		}
	}
	
	// Fill event cells with accent color
	eventCells := []struct{ col, row, w, h int }{
		{2, 1, 1, 1}, {4, 1, 1, 1}, {1, 2, 1, 2}, {5, 3, 1, 1},
		{3, 4, 1, 1}, {0, 1, 1, 1}, {6, 2, 1, 1},
	}
	for _, ec := range eventCells {
		x := gridX + ec.col*cellSize + 2
		y := gridY + ec.row*cellSize + 2
		w, h := ec.w*(cellSize-4), ec.h*(cellSize-4)
		for i := 0; i < w; i++ {
			for j := 0; j < h; j++ {
				if x+i < width && y+j < height {
					img.Set(x+i, y+j, accentColor)
				}
			}
		}
	}
	
	// SYNC ARROWS - circular arrows around the calendar
	// Top-right arrow (clockwise)
	drawCircularArrow(img, width*3/4, gridY-cellSize, 32, 2, accentColor, true)
	// Bottom-left arrow (counter-clockwise)
	drawCircularArrow(img, width/4, gridY+gridHeight+cellSize, 32, 2, accentColor, false)
	
	// Save to file
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

func drawCircularArrow(img *image.RGBA, cx, cy, radius, thickness int, c color.Color, clockwise bool) {
	step := 5
	startAngle, endAngle := 0, 360
	
	if clockwise {
		startAngle = 45
		endAngle = 315
	} else {
		startAngle = 225
		endAngle = 495
	}
	
	for angle := startAngle; angle <= endAngle; angle += step {
		rad := float64(angle) * math.Pi / 180.0
		x := cx + int(float64(radius)*math.Cos(rad))
		y := cy + int(float64(radius)*math.Sin(rad))
		for t := 0; t <= thickness; t++ {
			for a := -thickness/2; a <= thickness/2; a++ {
				dx := int(float64(t) * math.Cos(rad))
				dy := int(float64(t) * math.Sin(rad))
				if x+dx >= 0 && x+dx < 512 && y+dy >= 0 && y+dy < 512 {
					img.Set(x+dx, y+dy, c)
				}
			}
		}
	}
	
	arrowAngle := float64(endAngle-45) * math.Pi / 180.0
	for length := 0; length <= radius/2; length += 2 {
		for offset := -thickness; offset <= thickness; offset++ {
			x := cx + int((float64(radius)+float64(length))*math.Cos(arrowAngle))
			y := cy + int((float64(radius)+float64(length))*math.Sin(arrowAngle))
			if x >= 0 && x < 512 && y >= 0 && y < 512 {
				img.Set(x, y, c)
			}
		}
	}
}
