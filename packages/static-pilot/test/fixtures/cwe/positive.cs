using System.Net.Http;
using System.Data.SqlClient;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
class UnsafeExample {
 void Run(string input, System.IO.Stream stream) {
  var handler = new HttpClientHandler();
  handler.ServerCertificateCustomValidationCallback = (a,b,c,d) => true;
  var command = new SqlCommand($"SELECT * FROM t WHERE id={input}");
  BinaryFormatter formatter = new BinaryFormatter();
  formatter.Deserialize(stream);
  var cipher = DES.Create();
  DirectorySearcher searcher = new DirectorySearcher();
  searcher.Filter = "(cn=" + input + ")";
  var connection = new SqlConnection($"Server={input};Database=app");
  XmlReaderSettings settings = new XmlReaderSettings();
  settings.ValidationType = ValidationType.None;
  service.IncludeExceptionDetailInFaults = true;
  var credential = new NetworkCredential("fixture-user", "fixture-only-password");
  HttpClient client = new HttpClient();
  client.GetAsync(Request.Query["url"]);
  Activator.CreateInstance(Type.GetType(Request.Query["class"]));
 }
}
