using AuthServer.Models;
using MongoDB.Driver;

namespace AuthServer.Services;

public class MongoDbService
{
    private readonly IMongoDatabase _database;
    private readonly IMongoCollection<User> _users;
    private readonly IMongoCollection<AuditLog> _auditLogs;

    public MongoDbService(IConfiguration configuration)
    {
        var connectionString = configuration.GetValue<string>("MongoDbSettings:ConnectionString")
            ?? "mongodb://localhost:27017";
        var databaseName = configuration.GetValue<string>("MongoDbSettings:DatabaseName")
            ?? "AuthBaselineDb";

        var client = new MongoClient(connectionString);
        _database = client.GetDatabase(databaseName);
        _users = _database.GetCollection<User>("Users");
        _auditLogs = _database.GetCollection<AuditLog>("AuditLogs");

        // 创建唯一索引：用户名
        var indexKeys = Builders<User>.IndexKeys.Ascending(u => u.Username);
        var indexOptions = new CreateIndexOptions { Unique = true };
        _users.Indexes.CreateOne(new CreateIndexModel<User>(indexKeys, indexOptions));

        // 预置管理员账号（如果不存在），使用同步方法避免构造函数中 .Wait() 死锁
        SeedAdmin();
    }

    private void SeedAdmin()
    {
        var admin = _users.Find(u => u.Username == "admin").FirstOrDefault();
        if (admin == null)
        {
            var hash = BCrypt.Net.BCrypt.HashPassword("Admin123");
            _users.InsertOne(new User
            {
                Username = "admin",
                PasswordHash = hash,
                Status = UserStatus.Enabled,
                IsAdmin = true,
                CreatedAt = DateTime.UtcNow
            });
        }
    }

    public IMongoCollection<User> Users => _users;
    public IMongoCollection<AuditLog> AuditLogs => _auditLogs;
}
