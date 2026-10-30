package caldav

import (
	"io"
	"log"
)

func logSet(w io.Writer) { log.SetOutput(w) }
