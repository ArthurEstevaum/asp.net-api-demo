using System.Text;
using Azure;
using Azure.Communication.Email;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using MinhaApiJwt.Models;

var builder = WebApplication.CreateBuilder(args);
var configuration = builder.Configuration;

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(configuration.GetConnectionString("DefaultConnection"))
);

builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

builder.Services.AddAuthentication(options =>
{
    // A classe JwtBearerDefaults vem do namespace Microsoft.AspNetCore.Authentication.JwtBearer
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})

// O método .AddJwtBearer() é um método de extensão que se aplica ao AuthenticationBuilder.
// Este método vem do namespace Microsoft.AspNetCore.Authentication.JwtBearer.
.AddJwtBearer(options =>
{
    // A classe TokenValidationParameters vem do namespace Microsoft.IdentityModel.Tokens
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidateAudience = true,
        ValidAudience = builder.Configuration["Jwt:Audience"],
        ValidateIssuerSigningKey = true,
        // A classe SymmetricSecurityKey vem de Microsoft.IdentityModel.Tokens
        // A classe Encoding vem de System.Text
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"] ?? "")),
        ValidateLifetime = true
    };
});

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddAuthorization();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "API JWT Demo", Version = "v1" });
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "Insira o token JWT no formato: Bearer {seu token}"
    });
    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});
builder.Services.AddControllers();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.UseHttpsRedirection();

string connectionString = builder.Configuration["ConnectionStrings:AzureEmailService"] ?? "";
var emailClient = new EmailClient(connectionString);


var emailMessage = new EmailMessage(
    senderAddress: "DoNotReply@beholder.cloud",
    content: new EmailContent("Test Email")
    {
        PlainText = "Hello world via email.",
        Html = @"
		<html>
			<body>
				<h1>Hello world via email.</h1>
                <br />
                <p>Sending hello from .net</p>
			</body>
		</html>"
    },
    recipients: new EmailRecipients(new List<EmailAddress> { new EmailAddress("fulano@example.com") }));
    

EmailSendOperation emailSendOperation = emailClient.Send(
    WaitUntil.Completed,
    emailMessage);

app.Run();
