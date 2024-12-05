// Create a new HTTP handler for the "/test" path.
// This handler calls the preHandler function.
http.HandleFunc("/test", preHandler)

// Open the localhost URL in the default browser.
OpenBrowser(fmt.Sprintf("http://localhost:%d", freePort))

// Start the HTTP server on the free port.
// ListenAndServe will block execution, so no code after this will run.
err = http.ListenAndServe(fmt.Sprintf("127.0.0.1:%d", freePort), nil)
//
if err != nil {
    // If there's an error, print it out.
    // Since we're panicking, this will also exit the program.
    panic(fmt.Sprintf("Error starting server: %s", err))
}
