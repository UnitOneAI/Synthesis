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
 }
}
