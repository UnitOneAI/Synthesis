// Static fixture; intentionally incomplete application code.
[Authorize]
[HttpGet("/reports")]
public object Reports() {
  using var connection = new SqlConnection(settings);
  return query.ExecuteReader();
}
channel.BasicConsume(queue, handler);
var store = new X509Store(name);
