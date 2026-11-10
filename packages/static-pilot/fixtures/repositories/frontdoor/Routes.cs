// Static fixture only. Synthesis must never compile or execute this file.
app.UseAuthentication();
app.UseAuthorization();
app.MapGet("/reports", () => client.GetAsync(destination));
app.MapPost("/jobs", () => channel.BasicPublish(exchange, key, payload));
