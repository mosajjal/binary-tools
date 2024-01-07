package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

var baseURL = "https://github.com/mosajjal/binary-tools/blob/master/"

func handleURL(c *gin.Context, folders ...string) {
	path := ""
	if folders[0] == "" {
		folders = folders[1:]
	}
	if folders[0] != "arm" && folders[0] != "x64" {
		// prepend x64 to folders
		folders = append([]string{"x64"}, folders...)
	}

	for _, folder := range folders {
		if folder == "" {
			continue
		}
		fmt.Println(path)
		path = path + folder + "/"
	}

	u := baseURL + path + c.Param("binary") + "?raw=true"
	fmt.Println(u)
	resp, err := http.Get(u)
	if err != nil {
		c.Err()
	}
	if resp.StatusCode != http.StatusOK {
		c.Status(404)
		return
	}
	defer resp.Body.Close()

	// clientGone := c.Request.Context().Done()
	c.Stream(func(w io.Writer) bool {
		// TODO: deal with clientGone
		// case <-clientGone:
		// 	return false
		_, err := io.Copy(c.Writer, resp.Body)
		return err != nil
	})

}

func main() {
	apiRoutes := gin.Default()

	apiRoutes.GET("/*path", func(c *gin.Context) {
		handleURL(c, strings.Split(c.Param("path"), "/")...)
	})

	apiRoutes.Run()
}
