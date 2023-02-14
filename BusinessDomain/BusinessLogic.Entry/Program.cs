using BusinessLogic.Application.DependencyInjection;
using BusinessLogic.Entry.Models;
using BusinessLogic.Entry.ServiceConfigurations;
using BusinessLogic.Infrastructure.Authorization;
using BusinessLogic.Infrastructure.DependencyInjection;
using BusinessLogic.Persistence;
using BusinessLogic.Persistence.DependencyInjection;
using BusinessLogic.Presentation.Controllers;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

builder.Host.ConfigureLogging((ctx, lc) =>
{
    lc.AddConsole();
});

// Add services to the container.

builder.Services.AddControllers().AddApplicationPart(typeof(HubController).Assembly)
.AddControllersAsServices();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services
    .AddPersistence(builder.Configuration)
    .AddApplication()
    .AddInfrastructure();

Jwt jwt = new();
builder.Configuration.GetSection("Jwt").Bind(jwt);
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(options =>
{
    options.TokenValidationParameters = new()
    {
        ValidIssuer = jwt.Issuer,
        ValidAudience = jwt.Audience,
        ValidateIssuer = true,
        ValidateAudience = true,
        IssuerSigningKey = new SymmetricSecurityKey(Base64UrlEncoder.DecodeBytes(jwt.Key)),
        ValidateIssuerSigningKey = true,
    };
});

builder.Services.AddCorsConfiguration();
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("CanJoinRoom", policyBuilder => policyBuilder.AddRequirements(new CanJoinRoomRequirement()));
});

var app = builder.Build();
using (var serviceScope = app.Services.GetService<IServiceScopeFactory>()?.CreateScope())
{
    var context = serviceScope?.ServiceProvider.GetRequiredService<ApplicationDbContext>()!;

    context.Database.Migrate();

}
// Configure the HTTP request pipeline.
// if (app.Environment.IsDevelopment())
// {
app.UseSwagger();
app.UseSwaggerUI();
// }

// app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.UseCors(CorsConfiguration.CorsPolicyName);
app.MapControllers();

app.Run();
