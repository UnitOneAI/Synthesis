using System.Net.Http;
using System.Data.SqlClient;
using System.Security.Cryptography;
class SafeExample {
 void Run(string input) {
  var handler = new HttpClientHandler();
  var command = new SqlCommand("SELECT * FROM t WHERE id=@id");
  command.Parameters.AddWithValue("@id", input);
  var cipher = Aes.Create();
  DirectorySearcher searcher = new DirectorySearcher();
  searcher.Filter = "(objectClass=user)";
  var builder = new SqlConnectionStringBuilder();
  builder.DataSource = input;
  var connection = new SqlConnection(builder.ConnectionString);
  XmlReaderSettings settings = new XmlReaderSettings();
  settings.ValidationType = ValidationType.Schema;
  service.IncludeExceptionDetailInFaults = false;
  var credential = new NetworkCredential("user", secretProvider.Read());
  HttpClient client = new HttpClient();
  client.GetAsync("https://trusted.example/status");
  Activator.CreateInstance(typeof(ApprovedType));
 }
}
