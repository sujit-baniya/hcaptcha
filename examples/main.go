package main

import (
	"github.com/sujit-baniya/hcaptcha"
	"log"

	"github.com/gofiber/fiber/v2"
)

func main() {
	app := fiber.New()
	app.Get("/", func(c *fiber.Ctx) error {
		c.Set("Content-Type", "text/html")
		return c.SendString(`
	<script src="https://js.hcaptcha.com/1/api.js" async defer></script>
	<form action="/" method="post">
		<div class="h-captcha" data-sitekey="<SITE_KEY>"></div>
		<button type="submit">Login</button>
	</form>`)
	})
	app.Post("/", hcaptcha.New(&hcaptcha.Config{
		Secret:  "<SECRET_KEY>",
		SiteKey: "<SITE_KEY>",
	}), func(c *fiber.Ctx) error {
		return c.SendString("Good!")
	})

	log.Fatal(app.Listen(":3000"))
}
