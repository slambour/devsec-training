


vertx.createHttpServer().requestHandler({ req ->
  if (req.uri() == "/") {
    // Serve the index page
    req.response().sendFile("index.html")
  } else if (req.uri().startsWith("/form")) {
    //req.response().putHeader('X-XSS-Protection', '1; mode=block')
    req.response().setChunked(true)
    req.setExpectMultipart(true)
    req.endHandler({ v ->
      req.response().write('<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"')
      req.response().write('<html><head><title></title></head><body>')
      req.formAttributes().names().each { attr ->
        req.response().write("<div>Got attr ${attr} :</div>")

        req.response().write("<div>${req.formAttributes().get(attr)}</div>")
      }
      req.response().write('</body></html>')
      req.response().end()
    })
  } else {
    req.response().setStatusCode(404).end()
  }
}).listen(8080)