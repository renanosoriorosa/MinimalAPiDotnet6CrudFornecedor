using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.OpenApi.Models;
using MinimalAPI.Data;
using MinimalAPI.Models;
using MiniValidation;
using NetDevPack.Identity;
using NetDevPack.Identity.Jwt;
using NetDevPack.Identity.Model;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "Minimal API Sample",
        Description = "Developed by Renan Osorio da Rosa",
        Contact = new OpenApiContact { Name = "Renan Osorio", Email = "renanosoriogd@gmail.com" },
        License = new OpenApiLicense { Name = "MIT", Url = new Uri("https://opensource.org/licenses/MIT") }
    });

    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "Insira o token JWT desta maneira: Bearer {seu token}",
        Name = "Authorization",
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey
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
            new string[] {}
        }
    });
});

builder.Services.AddDbContext<MinimalContextDb>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("AppContext")));

builder.Services.AddIdentityEntityFrameworkContextConfiguration(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("AppContext"),
    b => b.MigrationsAssembly("MinimalAPI")));

builder.Services.AddIdentityConfiguration();
builder.Services.AddJwtConfiguration(builder.Configuration, "AppSettings");

builder.Services.AddAuthorization(options =>
    {
        options.AddPolicy("ExcluirFornecedor", policy => policy.RequireClaim("ExcluirFornecedor"));
    }
);

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseAuthConfiguration();
app.UseHttpsRedirection();

app.MapPost("/registro", [AllowAnonymous] async
    (SignInManager<IdentityUser> signInManager,
    UserManager<IdentityUser> userManager,
    IOptions<AppJwtSettings> appJwtSettings,
    RegisterUser registerUser
    ) =>
{
    if(registerUser == null)
        return Results.BadRequest("Usuário não informado.");

    if (!MiniValidator.TryValidate(registerUser, out var errors))
        return Results.ValidationProblem(errors);

    var user = new IdentityUser { 
        UserName = registerUser.Email,
        Email = registerUser.Email,
        EmailConfirmed = true
    };

    var result = await userManager.CreateAsync(user, registerUser.Password);

    if (!result.Succeeded)
        return Results.BadRequest(result.Errors);

    var jwt = new JwtBuilder()
        .WithUserManager(userManager)
        .WithJwtSettings(appJwtSettings.Value)
        .WithEmail(user.Email)
        .WithJwtClaims()
        .WithUserClaims()
        .WithUserRoles()
        .BuildUserResponse();

    return Results.Ok(jwt);
})
.ProducesValidationProblem()
.Produces(StatusCodes.Status400BadRequest)
.Produces<Fornecedor>(StatusCodes.Status200OK)
.WithName("RegistroUsuario")
.WithTags("Usuario");

app.MapPost("/login", [AllowAnonymous] async
    (SignInManager<IdentityUser> signInManager,
    UserManager<IdentityUser> userManager,
    IOptions<AppJwtSettings> appJwtSettings,
    LoginUser loginUser
    ) =>
{
    if (loginUser == null)
        return Results.BadRequest("Usuário não informado.");

    if (!MiniValidator.TryValidate(loginUser, out var errors))
        return Results.ValidationProblem(errors);

    var result = await signInManager.PasswordSignInAsync(loginUser.Email, loginUser.Password, true, true);

    if (result.IsLockedOut)
        return Results.BadRequest("Usuário bloqueado.");

    if (!result.Succeeded)
        return Results.BadRequest("Usuário ou senha inválidos.");

    var jwt = new JwtBuilder()
        .WithUserManager(userManager)
        .WithJwtSettings(appJwtSettings.Value)
        .WithEmail(loginUser.Email)
        .WithJwtClaims()
        .WithUserClaims()
        .WithUserRoles()
        .BuildUserResponse();

    return Results.Ok(jwt);
})
.ProducesValidationProblem()
.Produces(StatusCodes.Status400BadRequest)
.Produces<Fornecedor>(StatusCodes.Status200OK)
.WithName("LoginUsuario")
.WithTags("Usuario");

app.MapGet("/fornecedor", [AllowAnonymous] async
    (MinimalContextDb _context) =>
    await _context.Fornecedor.ToListAsync())
    .WithName("GetFornecedor")
    .WithTags("Fornecedor");

app.MapGet("/fornecedor/{id}", [Authorize]
    async (Guid id, MinimalContextDb _context) =>
    await _context.Fornecedor.FindAsync(id)
        is Fornecedor fornecedor
            ? Results.Ok(fornecedor)
            : Results.NotFound())
    .Produces<Fornecedor>(StatusCodes.Status200OK)
    .Produces(StatusCodes.Status404NotFound)
    .WithName("GetFornecedorPorId")
    .WithTags("Fornecedor");

app.MapPost("/fornecedor", [Authorize]
    async (MinimalContextDb _context, Fornecedor fornecedor) =>
    {
        if (!MiniValidator.TryValidate(fornecedor, out var errors))
            return Results.ValidationProblem(errors);

        _context.Fornecedor.Add(fornecedor);
        var result = await _context.SaveChangesAsync();

        return result > 0
            ? Results.Created($"/fornededor/{fornecedor.Id}", fornecedor)
            : Results.BadRequest("Falha ao salvar o registro.");

    })
    .ProducesValidationProblem()
    .Produces<Fornecedor>(StatusCodes.Status201Created)
    .Produces(StatusCodes.Status400BadRequest)
    .WithName("PostFornecedor")
    .WithTags("Fornecedor");

app.MapPut("/fornecedor/{id}", [Authorize]
async (
        Guid id,
        MinimalContextDb _context, 
        Fornecedor fornecedor) =>
    {
        var fornecedorBanco = await _context.Fornecedor
                                    .AsNoTracking()
                                    .FirstOrDefaultAsync(obj => obj.Id == id);

        if (fornecedorBanco == null)
            return Results.NotFound();

        if (!MiniValidator.TryValidate(fornecedor, out var errors))
            return Results.ValidationProblem(errors);

        _context.Fornecedor.Update(fornecedor);
        var result = await _context.SaveChangesAsync();

        return result > 0
            ? Results.NoContent()
            : Results.BadRequest("Falha ao editar o registro.");

    })
    .ProducesValidationProblem()
    .Produces<Fornecedor>(StatusCodes.Status204NoContent)
    .Produces(StatusCodes.Status400BadRequest)
    .WithName("PutFornecedor")
    .WithTags("Fornecedor");

app.MapDelete("/fornecedor/{id}", [Authorize]
async (
        Guid id,
        MinimalContextDb _context) =>
    {
        var fornecedorBanco = await _context.Fornecedor.FindAsync(id);

        if (fornecedorBanco == null)
            return Results.NotFound();

        _context.Fornecedor.Remove(fornecedorBanco);
        var result = await _context.SaveChangesAsync();

        return result > 0
            ? Results.NoContent()
            : Results.BadRequest("Falha ao remover o registro.");

    })
    .ProducesValidationProblem()
    .Produces<Fornecedor>(StatusCodes.Status204NoContent)
    .Produces(StatusCodes.Status400BadRequest)
    .RequireAuthorization("ExcluirFornecedor")
    .WithName("DeleteFornecedor")
    .WithTags("Fornecedor");

app.Run();