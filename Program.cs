using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using ProductsAPI.Models;

var MyAllowSpecificOrigins = "_myAllowSpecificOrigins";
var builder = WebApplication.CreateBuilder(args);

// CORS politikası ekleme
builder.Services.AddCors(options => {
    options.AddPolicy(MyAllowSpecificOrigins,
     policy => {
             policy.WithOrigins("http://127.0.0.1:5500")
            .AllowAnyHeader()
            .AllowAnyMethod();
    });
});

// SQLite veritabanı bağlamını yapılandırma
builder.Services.AddDbContext<ProductsContext>(x => x.UseSqlite("Data Source=products.db"));

// Kimlik yönetimi servislerini yapılandırma
builder.Services.AddIdentity<AppUser, AppRole>().AddEntityFrameworkStores<ProductsContext>();

// Kimlik doğrulama seçeneklerini yapılandırma
builder.Services.Configure<IdentityOptions>(options =>  {
    options.Password.RequiredLength = 6; // Şifre için minimum uzunluk
    options.Password.RequireNonAlphanumeric = false; // Alfasayısal olmayan karakter gerektirme
    options.Password.RequireLowercase = false; // Küçük harf gerektirme
    options.Password.RequireUppercase = false; // Büyük harf gerektirme
    options.Password.RequireDigit = false; // Rakam gerektirme

    options.User.RequireUniqueEmail = true; // Benzersiz e-posta gereksinimi
    options.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+"; // İzin verilen kullanıcı adı karakterleri

    options.Lockout.MaxFailedAccessAttempts = 5; // Başarısız giriş denemeleri sonrası kilitlenme sayısı
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5); // Kilitlenme süresi
});

// JWT kimlik doğrulama servisini ekleme ve yapılandırma
builder.Services.AddAuthentication(x => {
    x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(x => {
    x.RequireHttpsMetadata = false; // HTTPS gereksinimi olmadan çalışmasını sağla
    x.TokenValidationParameters = new TokenValidationParameters 
    {
        ValidateIssuer = false, // Issuer (Token üreticisi) doğrulamasını devre dışı bırak
        ValidIssuer = "mcdtkn.com", // Geçerli bir issuer
        ValidateAudience = false, // Audience (Token tüketicisi) doğrulamasını devre dışı bırak
        ValidAudience = "", // Geçerli bir audience
        ValidAudiences = new string[] { "a","b"}, // Geçerli audienceler
        ValidateIssuerSigningKey = true, // İmza anahtarını doğrula
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(
            builder.Configuration.GetSection("AppSettings:Secret").Value ?? "")), // JWT imzalama anahtarı
        ValidateLifetime = true // Token süresini doğrula
    };
});

// MVC Controller servislerini ekleme
builder.Services.AddControllers();

// Swagger/OpenAPI desteğini ekleme
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(option =>
{
    option.SwaggerDoc("v1", new OpenApiInfo { Title = "Demo API", Version = "v1" }); // Swagger dokümantasyonu için temel yapılandırma
    option.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        In = ParameterLocation.Header, // JWT token'ını HTTP başlığında bekle
        Description = "Please enter a valid token", // Açıklama
        Name = "Authorization", // Başlık adı
        Type = SecuritySchemeType.Http, // Güvenlik şeması türü
        BearerFormat = "JWT", // Bearer formatı
        Scheme = "Bearer" // Şema adı
    });
    option.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type=ReferenceType.SecurityScheme, // Referans tipi
                    Id="Bearer" // Referans ID
                }
            },
            new string[]{} // Gerekli yetkiler
        }
    });
});

var app = builder.Build();

// Geliştirme ortamında iseniz Swagger arayüzünü etkinleştir
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthentication(); // Kimlik doğrulama middleware'ini ekle
app.UseRouting(); // Yönlendirme middleware'ini ekle
app.UseCors(MyAllowSpecificOrigins); // CORS middleware'ini ekle
app.UseAuthorization(); // Yetkilendirme middleware'ini ekle
app.MapControllers(); // Kontrolcüleri yönlendirme

app.Run(); // Uygulamayı çalıştır
