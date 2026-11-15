using System.Net.Http;
using System.Data.SqlClient;
using System.Security.Cryptography;
class SafeExample {
 void Run(string input) {
  var handler = new HttpClientHandler();
  var command = new SqlCommand("SELECT * FROM t WHERE id=@id");
  command.Parameters.AddWithValue("@id", input);
  var cipher = Aes.Create();
 }
}
