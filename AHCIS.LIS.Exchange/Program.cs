using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Scalar.AspNetCore;
using System.Diagnostics;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using JwtRegisteredClaimNames = System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames;


var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOpenApi();
builder.Services.AddEndpointsApiExplorer();


builder.Services.Configure<LisJwtOptions>(opt =>
{
    var jwtSection = builder.Configuration.GetSection("LIS:Jwt");

    opt.SigningKey = jwtSection["SigningKey"] ?? "";
    opt.Lifetime = jwtSection["Lifetime"] ?? "00:10:00";
    opt.Audience = jwtSection["Audience"] ?? "lis.exchange";

    // clé: "Refresh-ExpirationInDays"
    var red = jwtSection["Refresh-ExpirationInDays"];
    opt.RefreshExpirationInDays = int.TryParse(red, out var days) ? days : 1;
});


// ========= OIDC/SSO settings =========
string EncodeUrl(string url) => url.Replace(" ", "%20");

var clientId = "5c8c2383-99c1-49f9-ba07-296eb384589a";
var clientSecret = "HbubTr5yTQzj+EUZk/U8za+VaPP/XxFcc+9Oyvhm4EY=";
var issuer = "https://devwebsso.rcu.gov.sa";

var authorizationEndpoint = EncodeUrl("https://devwebsso.rcu.gov.sa/affwebservices/CASSO/oidc/livestock identification System/authorize");
var tokenEndpoint = EncodeUrl("https://devwebsso.rcu.gov.sa/affwebservices/CASSO/oidc/livestock identification System/token");
var userInfoEndpoint = EncodeUrl("https://devwebsso.rcu.gov.sa/affwebservices/CASSO/oidc/livestock identification System/userinfo");
var jwksUri = EncodeUrl("https://devwebsso.rcu.gov.sa/affwebservices/CASSO/oidc/livestock identification System/jwks");

// ========= Auth "Smart": Bearer si Authorization: Bearer, sinon Cookie =========
builder.Services
    .AddAuthentication(options =>
    {
        options.DefaultScheme = "Smart";
        options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
    })
    .AddPolicyScheme("Smart", "Bearer or Cookie", options =>
    {
        options.ForwardDefaultSelector = ctx =>
        {
            var auth = ctx.Request.Headers.Authorization.ToString();
            if (!string.IsNullOrWhiteSpace(auth) &&
                auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                return JwtBearerDefaults.AuthenticationScheme;

            return CookieAuthenticationDefaults.AuthenticationScheme;
        };
    })
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
    {
        options.ResponseType = OpenIdConnectResponseType.Code;

        options.ClientId = clientId;
        options.ClientSecret = clientSecret;
        options.CallbackPath = "/api/v1/SsoCallback";

        options.Scope.Clear();
        options.Scope.Add("openid");

        options.SaveTokens = true;
        options.GetClaimsFromUserInfoEndpoint = true;
        options.UsePkce = true;

        options.Configuration = new OpenIdConnectConfiguration
        {
            Issuer = issuer,
            AuthorizationEndpoint = authorizationEndpoint,
            TokenEndpoint = tokenEndpoint,
            UserInfoEndpoint = userInfoEndpoint,
            JwksUri = jwksUri,
        };

        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = issuer,
            ValidateAudience = false,
            ValidateLifetime = true,
            NameClaimType = ClaimTypes.Name,
            RoleClaimType = ClaimTypes.Role
        };
    })
    .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, options =>
    {
        options.RequireHttpsMetadata = true;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = issuer,
            ValidateAudience = false,
            ValidateLifetime = true
        };

        // JWKS direct (si JWT). Si tokens opaques => utiliser introspection.
        options.Configuration = new OpenIdConnectConfiguration
        {
            Issuer = issuer,
            JwksUri = jwksUri
        };
    });

builder.Services.AddSingleton<RefreshTokenStore>();

builder.Services
    .AddAuthentication() // on ne change pas ton "Smart" existant; on ajoute un scheme en plus
    .AddJwtBearer("LisJwt", options =>
    {
        var jwt = builder.Configuration.GetSection("LIS:Jwt");
        var signingKey = jwt["SigningKey"] ?? "";

        options.RequireHttpsMetadata = true;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false, // pas fourni dans config; tu peux mettre un issuer si tu veux
            ValidateAudience = true,
            ValidAudience = jwt["Audience"],
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signingKey)),
            ClockSkew = TimeSpan.FromSeconds(30)
        };
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("LisBearerOnly", policy =>
    {
        policy.AddAuthenticationSchemes("LisJwt");
        policy.RequireAuthenticatedUser();
    });
});

var app = builder.Build();

// OpenAPI json + Scalar
app.MapOpenApi();
app.MapScalarApiReference(o =>
{
   
    o.WithTitle("LIS Exchange API")
     .WithDefaultHttpClient(ScalarTarget.CSharp, ScalarClient.AsyncHttp);
});

//app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

// ===========================
// LIS SSO Auth endpoints (JWT + Refresh)
// ===========================
var lisAuth = app.MapGroup("/lis/api/v1/auth")
    .WithTags("AHCP Auth"); // visible dans Scalar

lisAuth.MapPost("/token", async (
    LoginRequest req,
    IConfiguration cfg,
    IOptions<LisJwtOptions> opt,
    RefreshTokenStore rtStore) =>
{
    if (string.IsNullOrWhiteSpace(req.username) || string.IsNullOrWhiteSpace(req.password))
        return Api.Error(400, "VALIDATION_ERROR", "Username and password are required.");

    // users from config: LIS:Users:{username}:Password
    var expectedPassword = cfg[$"LIS:Users:{req.username}:Password"];
    if (string.IsNullOrEmpty(expectedPassword) || expectedPassword != req.password)
        return Api.Error(401, "INVALID_CREDENTIALS", "Invalid username or password.");

    var options = opt.Value;
    if (string.IsNullOrWhiteSpace(options.SigningKey) || options.SigningKey.Contains("***"))
        return Api.Error(500, "CONFIG_ERROR", "JWT SigningKey is not configured.");

    var accessToken = LisJwt.CreateAccessToken(req.username, options);

    var refreshToken = LisJwt.CreateRefreshToken();
    var refreshExpires = DateTimeOffset.UtcNow.AddDays(options.RefreshExpirationInDays);

    rtStore.Save(new RefreshTokenEntry(refreshToken, req.username, refreshExpires));

    var expiresIn = (int)LisJwt.ParseLifetime(options.Lifetime).TotalSeconds;

    return Api.Ok(new TokenResponse(accessToken, refreshToken, expiresIn));
});

lisAuth.MapPost("/refresh", (
    RefreshRequest req,
    IOptions<LisJwtOptions> opt,
    RefreshTokenStore rtStore) =>
{
    if (string.IsNullOrWhiteSpace(req.refresh_token))
        return Api.Error(400, "VALIDATION_ERROR", "refresh_token is required.");

    if (!rtStore.TryGet(req.refresh_token, out var entry))
        return Api.Error(401, "INVALID_REFRESH_TOKEN", "Invalid refresh token.");

    if (entry.Revoked)
        return Api.Error(401, "REVOKED_REFRESH_TOKEN", "Refresh token has been revoked.");

    if (DateTimeOffset.UtcNow >= entry.ExpiresAtUtc)
        return Api.Error(401, "EXPIRED_REFRESH_TOKEN", "Refresh token has expired.");

    var options = opt.Value;
    var newAccessToken = LisJwt.CreateAccessToken(entry.Username, options);

    // rotation (recommandé): nouveau refresh, révoque l'ancien
    rtStore.Revoke(req.refresh_token);

    var newRefresh = LisJwt.CreateRefreshToken();
    var newRefreshExpires = DateTimeOffset.UtcNow.AddDays(options.RefreshExpirationInDays);
    rtStore.Save(new RefreshTokenEntry(newRefresh, entry.Username, newRefreshExpires));

    var expiresIn = (int)LisJwt.ParseLifetime(options.Lifetime).TotalSeconds;

    return Api.Ok(new TokenResponse(newAccessToken, newRefresh, expiresIn));
});

lisAuth.MapPost("/revoke", (
    RefreshRequest req,
    RefreshTokenStore rtStore) =>
{
    if (string.IsNullOrWhiteSpace(req.refresh_token))
        return Api.Error(400, "VALIDATION_ERROR", "refresh_token is required.");

    rtStore.Revoke(req.refresh_token);
    return Api.Ok(new { revoked = true });
});

// ===========================
// Fake store - AHCP Health data (AHCP -> LIS)
// Base required by doc: /lis/api/v1
// ===========================
var animalInterventions = new List<AnimalInterventionDto>
{
    new AnimalInterventionDto(
        AnimalId: "32465",
        InterventionId: "intv-9f1c2e2b",
        InterventionDate: DateTimeOffset.Parse("2025-12-22T10:15:00Z"),
        InterventionType: "VACCINATION",
        InterventionDescription: "FMD vaccine dose 1",
        Region: "ALULA",
        UpdatedAt: DateTimeOffset.Parse("2025-12-22T10:20:00Z"),
        IsDeleted: false,
        Medications: Array.Empty<MedicationAdministrationDto>(),
        DiagnosisRef: null,
        PerformedBy: "vet-001"
    ),
    new AnimalInterventionDto(
        AnimalId: "32465",
        InterventionId: "intv-anti-001",
        InterventionDate: DateTimeOffset.Parse("2025-12-23T08:30:00Z"),
        InterventionType: "ANTIBIOTIC_TREATMENT",
        InterventionDescription: "Mastitis treatment",
        Region: "ALULA",
        UpdatedAt: DateTimeOffset.Parse("2025-12-23T08:45:00Z"),
        IsDeleted: false,
        Medications: new[]
        {
            new MedicationAdministrationDto(
                ProductName: "Amoxicillin LA",
                ActiveSubstance: "Amoxicillin",
                AtcVetCode: "QJ01CA04",
                Dose: 15m,
                DoseUnit: "mg/kg",
                Route: "INTRAMUSCULAR",
                Frequency: "q24h",
                DurationDays: 3,
                BatchNumber: "LOT-2025-11-889",
                MarketingAuthorizationNumber: null,
                Withdrawal: new WithdrawalPeriodDto(
                    MilkWithdrawalHours: 72,
                    MeatWithdrawalDays: 14,
                    WithdrawalStartDate: DateTimeOffset.Parse("2025-12-23T08:30:00Z"),
                    Notes: null
                )
            )
        },
        DiagnosisRef: "dis-001",
        PerformedBy: "vet-002"
    )
};

var interventionChanges = new List<ChangeEnvelope<AnimalInterventionDto>>
{
    new ChangeEnvelope<AnimalInterventionDto>(
        Op: "UPSERT",
        ChangedAt: DateTimeOffset.Parse("2025-12-22T10:20:00Z"),
        Item: animalInterventions[0]
    ),
    new ChangeEnvelope<AnimalInterventionDto>(
        Op: "DELETE",
        ChangedAt: DateTimeOffset.Parse("2025-12-22T11:05:00Z"),
        Item: new AnimalInterventionDto(
            AnimalId: "32465",
            InterventionId: "intv-11111111",
            InterventionDate: null,
            InterventionType: null,
            InterventionDescription: null,
            Region: "ALULA",
            UpdatedAt: DateTimeOffset.Parse("2025-12-22T11:05:00Z"),
            IsDeleted: true,
            Medications: Array.Empty<MedicationAdministrationDto>(),
            DiagnosisRef: null,
            PerformedBy: null
        )
    )
};

var animalHealthStatuses = new List<AnimalStatusDto>
{
    new AnimalStatusDto(
        AnimalId: "32465",
        StatusId: "st-aaa",
        Status: "ACTIVE",
        StatusDate: DateTimeOffset.Parse("2025-12-22T09:00:00Z"),
        Reason: "Post-check",
        Region: "ALULA",
        UpdatedAt: DateTimeOffset.Parse("2025-12-22T09:01:00Z"),
        IsDeleted: false
    )
};

var animalStatusChanges = new List<ChangeEnvelope<AnimalStatusDto>>
{
    new ChangeEnvelope<AnimalStatusDto>(
        Op: "UPSERT",
        ChangedAt: DateTimeOffset.Parse("2025-12-22T09:01:00Z"),
        Item: animalHealthStatuses[0]
    )
};

var holdingHealthStatuses = new List<HoldingStatusDto>
{
    new HoldingStatusDto(
        HoldingId: "2510",
        StatusId: "hst-01",
        Status: "ACTIVE",
        StatusDate: DateTimeOffset.Parse("2025-12-01T00:00:00Z"),
        Reason: "Compliance verified",
        Region: "ALULA",
        UpdatedAt: DateTimeOffset.Parse("2025-12-01T00:10:00Z"),
        IsDeleted: false
    )
};

var holdingStatusChanges = new List<ChangeEnvelope<HoldingStatusDto>>
{
    new ChangeEnvelope<HoldingStatusDto>(
        Op: "DELETE",
        ChangedAt: DateTimeOffset.Parse("2025-12-22T12:00:00Z"),
        Item: new HoldingStatusDto(
            HoldingId: "2510",
            StatusId: "hst-99",
            Status: null,
            StatusDate: null,
            Reason: null,
            Region: "ALULA",
            UpdatedAt: DateTimeOffset.Parse("2025-12-22T12:00:00Z"),
            IsDeleted: true
        )
    )
};

var animalDiseaseRecords = new List<AnimalDiseaseRecordDto>
{
    new AnimalDiseaseRecordDto(
        AnimalId: "32465",
        DiseaseRecordId: "dis-001",
        DiseaseName: "Mastitis",
        DiseaseCode: "MASTITIS",
        OnsetDate: DateTimeOffset.Parse("2025-12-20T00:00:00Z"),
        DiagnosisDate: DateTimeOffset.Parse("2025-12-21T08:30:00Z"),
        Status: "CONFIRMED",
        Severity: "MODERATE",
        Notes: "Clinical signs + lab confirmation",
        Region: "ALULA",
        UpdatedAt: DateTimeOffset.Parse("2025-12-21T09:00:00Z"),
        IsDeleted: false
    )
};

var diseaseChanges = new List<ChangeEnvelope<AnimalDiseaseRecordDto>>
{
    new ChangeEnvelope<AnimalDiseaseRecordDto>(
        Op: "UPSERT",
        ChangedAt: DateTimeOffset.Parse("2025-12-22T12:10:00Z"),
        Item: new AnimalDiseaseRecordDto(
            AnimalId: "32465",
            DiseaseRecordId: "dis-002",
            DiseaseName: "Dermatophilosis",
            DiseaseCode: "DERMATOPHILOSIS",
            OnsetDate: null,
            DiagnosisDate: DateTimeOffset.Parse("2025-12-22T12:00:00Z"),
            Status: "SUSPECTED",
            Severity: null,
            Notes: null,
            Region: "ALULA",
            UpdatedAt: DateTimeOffset.Parse("2025-12-22T12:10:00Z"),
            IsDeleted: false
        )
    )
};

// ===========================
// AHCP API group (AHCP -> LIS)
// Base path from spec: /lis/api/v1
// Bearer only (machine-to-machine)
// ===========================


// ===========================
// Fake store (remplace par DB/repo)
// ===========================
var owners = new List<OwnerDto>
{
    new(
        Id: "20598313-b20e-4317-a5cd-d70810371a2d",
        Name: "OWNER_NAME",
        Email: null,
        Phone: "0599566688",
        TelephoneNumber: null,
        NationalOrIqamaId: "1037236963",
        AgricultureServicesCardNumber: null,
        OwnerType: "Natural Person",
        IsActive: true,
        SyncStatus: "SYNCED",
        LastSyncedAt: DateTimeOffset.Parse("2025-12-22T10:00:00Z")
    )
};

var holdings = new List<HoldingDto>
{
    new(
        Id: 2510,
        OwnerId: "20598313-b20e-4317-a5cd-d70810371a2d",
        HoldingName: "HOLDING_NAME",
        HoldingLegalTypeId: null,
        HoldingLegalType: null,
        HoldingIdentifierTRN: "03_00_052564",
        MewaNumber: null,
        Attachments: Array.Empty<object>(),
        PhysicalAddress: new AddressDto("العلا", "مغيراء", null, null, "المدينة", null, 26.42867, 38.113258),
        PostalAddress: new AddressDto("العلا", "مغيراء", null, null, "المدينة", null, null, null),
        IsActive: true,
        SyncStatus: "SYNCED",
        LastSyncedAt: DateTimeOffset.Parse("2025-12-22T10:00:00Z")
    )
};

var animals = new List<AnimalDto>
{
    new(
        Id: 32465,
        AddingReason: "Identification",
        RegistrationDate: DateTimeOffset.Parse("2025-12-22T00:00:00Z"),
        AnimalSpecies: "الاغنام",
        AnimalBreed: "نجدي",
        SpeciesAddingPurpose: "متعدد الأغراض",
        DateOfBirth: DateTimeOffset.Parse("2025-09-22T00:00:00Z"),
        IdDeviceType: null,
        AnimalID: "682030002048098",
        FatherID: null,
        MotherID: null,
        Sex: "Female",
        CountryOfOrigin: null,
        Attachments: Array.Empty<object>(),
        Description: null,
        HoldingId: 10,
        HoldingIdentifierTRN: "03_00_050005",
        SyncStatus: "SYNCED",
        LastSyncedAt: DateTimeOffset.Parse("2025-12-22T10:00:00Z")
    )
};


var ahcp = app.MapGroup("/lis/api/v1")
    .RequireAuthorization("LisBearerOnly")
    .WithTags("AHCP Animal Health");

// Optional health endpoint for token validation tests
ahcp.MapGet("/_ping", (HttpContext ctx) =>
{
    var correlationId = Api.GetOrCreateCorrelationId(ctx);
    return Api.Ok(new
    {
        message = "AHCP LIS API is reachable",
        correlationId
    });
});

// 2.1.1 Full intervention history for an animal
ahcp.MapGet("/animals/{animalId:int}/interventions", (HttpContext ctx, int animalId) =>
{
    if (!animals.Any(a => a.Id == animalId))
        return Api.Error(404, "ANIMAL_NOT_FOUND", "Animal not found.");

    var correlationId = Api.GetOrCreateCorrelationId(ctx);

    var items = animalInterventions
        .Where(x => string.Equals(x.AnimalId, animalId.ToString(CultureInfo.InvariantCulture), StringComparison.OrdinalIgnoreCase))
        .OrderBy(x => x.InterventionDate ?? x.UpdatedAt)
        .ToList();

    return Api.Ok(items, correlationId);
});

// 2.1.2 Intervention deltas since
ahcp.MapGet("/interventions/changes", (HttpContext ctx, string? since, string? region, int? page, int? pageSize) =>
{
    var sinceCheck = Api.ValidateSince(since);
    if (sinceCheck.error is not null)
        return Api.Error(400, sinceCheck.error.Value.code, sinceCheck.error.Value.message, sinceCheck.error.Value.details);

    var paging = Api.ValidatePaging(page, pageSize);
    if (paging.error is not null)
        return Api.Error(400, paging.error.Value.code, paging.error.Value.message, paging.error.Value.details);

    var correlationId = Api.GetOrCreateCorrelationId(ctx);
    var sinceUtc = sinceCheck.value!.Value;

    IEnumerable<ChangeEnvelope<AnimalInterventionDto>> q = interventionChanges
        .Where(x => x.ChangedAt > sinceUtc);

    if (!string.IsNullOrWhiteSpace(region))
    {
        q = q.Where(x => x.Item is not null &&
                         string.Equals(x.Item.Region, region, StringComparison.OrdinalIgnoreCase));
    }

    var ordered = q.OrderBy(x => x.ChangedAt).ToList();
    var total = ordered.Count;

    var items = ordered
        .Skip((paging.page - 1) * paging.pageSize)
        .Take(paging.pageSize)
        .ToList();

    var hasNext = (paging.page * paging.pageSize) < total;
    var nextSince = items.Count > 0 ? items.Max(x => x.ChangedAt).ToString("O") : sinceUtc.ToString("O");

    return Api.Ok(
        items,
        new Pagination(paging.page, paging.pageSize, total, hasNext),
        new ApiMeta(nextSince),
        correlationId
    );
});

// 2.2.1 Full animal status history
ahcp.MapGet("/animals/{animalId:int}/status", (HttpContext ctx, int animalId) =>
{
    if (!animals.Any(a => a.Id == animalId))
        return Api.Error(404, "ANIMAL_NOT_FOUND", "Animal not found.");

    var correlationId = Api.GetOrCreateCorrelationId(ctx);

    var items = animalHealthStatuses
        .Where(x => string.Equals(x.AnimalId, animalId.ToString(CultureInfo.InvariantCulture), StringComparison.OrdinalIgnoreCase))
        .OrderBy(x => x.StatusDate ?? x.UpdatedAt)
        .ToList();

    return Api.Ok(items, correlationId);
});

// 2.2.2 Animal status deltas since
ahcp.MapGet("/animals/status/changes", (HttpContext ctx, string? since, string? region, int? page, int? pageSize) =>
{
    var sinceCheck = Api.ValidateSince(since);
    if (sinceCheck.error is not null)
        return Api.Error(400, sinceCheck.error.Value.code, sinceCheck.error.Value.message, sinceCheck.error.Value.details);

    var paging = Api.ValidatePaging(page, pageSize);
    if (paging.error is not null)
        return Api.Error(400, paging.error.Value.code, paging.error.Value.message, paging.error.Value.details);

    var correlationId = Api.GetOrCreateCorrelationId(ctx);
    var sinceUtc = sinceCheck.value!.Value;

    IEnumerable<ChangeEnvelope<AnimalStatusDto>> q = animalStatusChanges
        .Where(x => x.ChangedAt > sinceUtc);

    if (!string.IsNullOrWhiteSpace(region))
    {
        q = q.Where(x => x.Item is not null &&
                         string.Equals(x.Item.Region, region, StringComparison.OrdinalIgnoreCase));
    }

    var ordered = q.OrderBy(x => x.ChangedAt).ToList();
    var total = ordered.Count;

    var items = ordered
        .Skip((paging.page - 1) * paging.pageSize)
        .Take(paging.pageSize)
        .ToList();

    var hasNext = (paging.page * paging.pageSize) < total;
    var nextSince = items.Count > 0 ? items.Max(x => x.ChangedAt).ToString("O") : sinceUtc.ToString("O");

    return Api.Ok(
        items,
        new Pagination(paging.page, paging.pageSize, total, hasNext),
        new ApiMeta(nextSince),
        correlationId
    );
});

// 2.3.1 Full holding status history
ahcp.MapGet("/holdings/{holdingId:int}/status", (HttpContext ctx, int holdingId) =>
{
    if (!holdings.Any(h => h.Id == holdingId))
        return Api.Error(404, "HOLDING_NOT_FOUND", "Holding not found.");

    var correlationId = Api.GetOrCreateCorrelationId(ctx);

    var items = holdingHealthStatuses
        .Where(x => string.Equals(x.HoldingId, holdingId.ToString(CultureInfo.InvariantCulture), StringComparison.OrdinalIgnoreCase))
        .OrderBy(x => x.StatusDate ?? x.UpdatedAt)
        .ToList();

    return Api.Ok(items, correlationId);
});

// 2.3.2 Holding status deltas since
ahcp.MapGet("/holdings/status/changes", (HttpContext ctx, string? since, string? region, int? page, int? pageSize) =>
{
    var sinceCheck = Api.ValidateSince(since);
    if (sinceCheck.error is not null)
        return Api.Error(400, sinceCheck.error.Value.code, sinceCheck.error.Value.message, sinceCheck.error.Value.details);

    var paging = Api.ValidatePaging(page, pageSize);
    if (paging.error is not null)
        return Api.Error(400, paging.error.Value.code, paging.error.Value.message, paging.error.Value.details);

    var correlationId = Api.GetOrCreateCorrelationId(ctx);
    var sinceUtc = sinceCheck.value!.Value;

    IEnumerable<ChangeEnvelope<HoldingStatusDto>> q = holdingStatusChanges
        .Where(x => x.ChangedAt > sinceUtc);

    if (!string.IsNullOrWhiteSpace(region))
    {
        q = q.Where(x => x.Item is not null &&
                         string.Equals(x.Item.Region, region, StringComparison.OrdinalIgnoreCase));
    }

    var ordered = q.OrderBy(x => x.ChangedAt).ToList();
    var total = ordered.Count;

    var items = ordered
        .Skip((paging.page - 1) * paging.pageSize)
        .Take(paging.pageSize)
        .ToList();

    var hasNext = (paging.page * paging.pageSize) < total;
    var nextSince = items.Count > 0 ? items.Max(x => x.ChangedAt).ToString("O") : sinceUtc.ToString("O");

    return Api.Ok(
        items,
        new Pagination(paging.page, paging.pageSize, total, hasNext),
        new ApiMeta(nextSince),
        correlationId
    );
});

// 6.1 Full disease history for an animal
ahcp.MapGet("/animals/{animalId:int}/diseases", (HttpContext ctx, int animalId) =>
{
    if (!animals.Any(a => a.Id == animalId))
        return Api.Error(404, "ANIMAL_NOT_FOUND", "Animal not found.");

    var correlationId = Api.GetOrCreateCorrelationId(ctx);

    var items = animalDiseaseRecords
        .Where(x => string.Equals(x.AnimalId, animalId.ToString(CultureInfo.InvariantCulture), StringComparison.OrdinalIgnoreCase))
        .OrderBy(x => x.DiagnosisDate ?? x.OnsetDate ?? x.UpdatedAt)
        .ToList();

    return Api.Ok(items, correlationId);
});

// 6.2 Disease deltas since
ahcp.MapGet("/diseases/changes", (HttpContext ctx, string? since, string? region, int? page, int? pageSize) =>
{
    var sinceCheck = Api.ValidateSince(since);
    if (sinceCheck.error is not null)
        return Api.Error(400, sinceCheck.error.Value.code, sinceCheck.error.Value.message, sinceCheck.error.Value.details);

    var paging = Api.ValidatePaging(page, pageSize);
    if (paging.error is not null)
        return Api.Error(400, paging.error.Value.code, paging.error.Value.message, paging.error.Value.details);

    var correlationId = Api.GetOrCreateCorrelationId(ctx);
    var sinceUtc = sinceCheck.value!.Value;

    IEnumerable<ChangeEnvelope<AnimalDiseaseRecordDto>> q = diseaseChanges
        .Where(x => x.ChangedAt > sinceUtc);

    if (!string.IsNullOrWhiteSpace(region))
    {
        q = q.Where(x => x.Item is not null &&
                         string.Equals(x.Item.Region, region, StringComparison.OrdinalIgnoreCase));
    }

    var ordered = q.OrderBy(x => x.ChangedAt).ToList();
    var total = ordered.Count;

    var items = ordered
        .Skip((paging.page - 1) * paging.pageSize)
        .Take(paging.pageSize)
        .ToList();

    var hasNext = (paging.page * paging.pageSize) < total;
    var nextSince = items.Count > 0 ? items.Max(x => x.ChangedAt).ToString("O") : sinceUtc.ToString("O");

    return Api.Ok(
        items,
        new Pagination(paging.page, paging.pageSize, total, hasNext),
        new ApiMeta(nextSince),
        correlationId
    );
});





// ===========================
// LIS API group (Base /api/v1/integration)
// ===========================
var lis = app.MapGroup("/api/v1/integration")
    .RequireAuthorization()
    .WithTags("LIS Registry");

// GET /owners
lis.MapGet("/owners", (bool? isActive, DateTimeOffset? modifiedSince, int? page, int? pageSize) =>
{
    var (p, ps, validationError) = Api.ValidatePaging(page, pageSize);
    if (validationError is not null)
        return Api.Error(400, validationError.Value.code, validationError.Value.message, validationError.Value.details);

    IEnumerable<OwnerDto> q = owners;

    if (isActive is not null) q = q.Where(x => x.IsActive == isActive.Value);
    if (modifiedSince is not null) q = q.Where(x => x.LastSyncedAt is not null && x.LastSyncedAt >= modifiedSince);

    var total = q.Count();
    var items = q.Skip((p - 1) * ps).Take(ps).ToList();
    var hasNext = (p * ps) < total;

    return Api.Ok(items, new Pagination(p, ps, total, hasNext));
});

// GET /owners/{ownerId}
lis.MapGet("/owners/{ownerId}", (string ownerId) =>
{
    var item = owners.FirstOrDefault(x => x.Id.Equals(ownerId, StringComparison.OrdinalIgnoreCase));
    return item is null
        ? Api.Error(404, "OWNER_NOT_FOUND", "Owner not found.")
        : Api.Ok(item);
});

// GET /holdings
lis.MapGet("/holdings", (bool? isActive, DateTimeOffset? modifiedSince, int? page, int? pageSize) =>
{
    var (p, ps, validationError) = Api.ValidatePaging(page, pageSize);
    if (validationError is not null)
        return Api.Error(400, validationError.Value.code, validationError.Value.message, validationError.Value.details);

    IEnumerable<HoldingDto> q = holdings;

    if (isActive is not null) q = q.Where(x => x.IsActive == isActive.Value);
    if (modifiedSince is not null) q = q.Where(x => x.LastSyncedAt is not null && x.LastSyncedAt >= modifiedSince);

    var total = q.Count();
    var items = q.Skip((p - 1) * ps).Take(ps).ToList();
    var hasNext = (p * ps) < total;

    return Api.Ok(items, new Pagination(p, ps, total, hasNext));
});

// GET /holdings/{holdingId}
lis.MapGet("/holdings/{holdingId:int}", (int holdingId) =>
{
    var item = holdings.FirstOrDefault(x => x.Id == holdingId);
    return item is null
        ? Api.Error(404, "HOLDING_NOT_FOUND", "Holding not found.")
        : Api.Ok(item);
});

// GET /animals
lis.MapGet("/animals", (DateTimeOffset? modifiedSince, int? page, int? pageSize) =>
{
    var (p, ps, validationError) = Api.ValidatePaging(page, pageSize);
    if (validationError is not null)
        return Api.Error(400, validationError.Value.code, validationError.Value.message, validationError.Value.details);

    IEnumerable<AnimalDto> q = animals;

    if (modifiedSince is not null) q = q.Where(x => x.LastSyncedAt is not null && x.LastSyncedAt >= modifiedSince);

    var total = q.Count();
    var items = q.Skip((p - 1) * ps).Take(ps).ToList();
    var hasNext = (p * ps) < total;

    return Api.Ok(items, new Pagination(p, ps, total, hasNext));
});

// GET /animals/{animalId}
lis.MapGet("/animals/{animalId:int}", (int animalId) =>
{
    var item = animals.FirstOrDefault(x => x.Id == animalId);
    return item is null
        ? Api.Error(404, "ANIMAL_NOT_FOUND", "Animal not found.")
        : Api.Ok(item);
});

// ===========================
// login/me/logout (tests interactifs)
// ===========================
var lisSSOAuth = app.MapGroup("/")
    .WithTags("LIS Auth");
lisSSOAuth.MapGet("/login", async (HttpContext ctx) =>
{
    await ctx.ChallengeAsync(OpenIdConnectDefaults.AuthenticationScheme, new AuthenticationProperties
    {
        RedirectUri = "/me"
    });
});

lisSSOAuth.MapGet("/me", (ClaimsPrincipal user) =>
{
    return Results.Ok(new
    {
        name = user.Identity?.Name ?? "(no name)",
        claims = user.Claims.Select(c => new { c.Type, c.Value })
    });
}).RequireAuthorization();

lisSSOAuth.MapGet("/logout", async (HttpContext ctx) =>
{
    await ctx.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    await ctx.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme);
    return Results.Ok("Logged out");
});

app.Run();

// ===========================
// Contracts
// ===========================
public sealed record ApiMeta(string? NextSince);

public sealed record ChangeEnvelope<T>(
    string Op,
    DateTimeOffset ChangedAt,
    T Item
);

public sealed record AnimalInterventionDto(
    string AnimalId,
    string InterventionId,
    DateTimeOffset? InterventionDate,
    string? InterventionType,
    string? InterventionDescription,
    string? Region,
    DateTimeOffset UpdatedAt,
    bool IsDeleted,
    IReadOnlyList<MedicationAdministrationDto> Medications,
    string? DiagnosisRef,
    string? PerformedBy
);

public sealed record MedicationAdministrationDto(
    string ProductName,
    string? ActiveSubstance,
    string? AtcVetCode,
    decimal? Dose,
    string? DoseUnit,
    string? Route,
    string? Frequency,
    int? DurationDays,
    string? BatchNumber,
    string? MarketingAuthorizationNumber,
    WithdrawalPeriodDto? Withdrawal
);

public sealed record WithdrawalPeriodDto(
    int? MilkWithdrawalHours,
    int? MeatWithdrawalDays,
    DateTimeOffset? WithdrawalStartDate,
    string? Notes
);

public sealed record AnimalStatusDto(
    string AnimalId,
    string StatusId,
    string? Status,
    DateTimeOffset? StatusDate,
    string? Reason,
    string? Region,
    DateTimeOffset UpdatedAt,
    bool IsDeleted
);

public sealed record HoldingStatusDto(
    string HoldingId,
    string StatusId,
    string? Status,
    DateTimeOffset? StatusDate,
    string? Reason,
    string? Region,
    DateTimeOffset UpdatedAt,
    bool IsDeleted
);

public sealed record AnimalDiseaseRecordDto(
    string AnimalId,
    string DiseaseRecordId,
    string DiseaseName,
    string? DiseaseCode,
    DateTimeOffset? OnsetDate,
    DateTimeOffset? DiagnosisDate,
    string Status,
    string? Severity,
    string? Notes,
    string? Region,
    DateTimeOffset UpdatedAt,
    bool IsDeleted
);



public sealed record ApiEnvelope<T>
{
    public bool Success { get; init; }
    public T? Data { get; init; }
    public Pagination? Pagination { get; init; }
    public ApiMeta? Meta { get; init; }
    public ApiError? Error { get; init; }
    public DateTimeOffset? Timestamp { get; init; }
    public string? TraceId { get; init; }
    public string? CorrelationId { get; init; }
}


public sealed record Pagination(int Page, int PageSize, int Total, bool HasNext);

public sealed record ApiError
{
    public string Code { get; init; } = default!;
    public string Message { get; init; } = default!;
    public List<ErrorDetail> Details { get; init; } = new List<ErrorDetail>();
}

public sealed record ErrorDetail(string Field, string Issue);

// DTOs
public sealed record OwnerDto(
    string Id,
    string Name,
    string? Email,
    string Phone,
    string? TelephoneNumber,
    string NationalOrIqamaId,
    string? AgricultureServicesCardNumber,
    string OwnerType,
    bool IsActive,
    string? SyncStatus,
    DateTimeOffset? LastSyncedAt
);

public sealed record HoldingDto(
    int Id,
    string OwnerId,
    string HoldingName,
    int? HoldingLegalTypeId,
    string? HoldingLegalType,
    string HoldingIdentifierTRN,
    string? MewaNumber,
    IReadOnlyList<object> Attachments,
    AddressDto PhysicalAddress,
    AddressDto PostalAddress,
    bool IsActive,
    string? SyncStatus,
    DateTimeOffset? LastSyncedAt
);

public sealed record AddressDto(
    string? Governorate,
    string? City,
    string? Street,
    string? StreetNumber,
    string? Region,
    string? Remarks,
    double? Latitude,
    double? Longitude
);

public sealed record AnimalDto(
    int Id,
    string AddingReason,
    DateTimeOffset RegistrationDate,
    string AnimalSpecies,
    string? AnimalBreed,
    string? SpeciesAddingPurpose,
    DateTimeOffset? DateOfBirth,
    string? IdDeviceType,
    string AnimalID,
    string? FatherID,
    string? MotherID,
    string Sex,
    string? CountryOfOrigin,
    IReadOnlyList<object> Attachments,
    string? Description,
    int HoldingId,
    string? HoldingIdentifierTRN,
    string? SyncStatus,
    DateTimeOffset? LastSyncedAt
);

public sealed class LisJwtOptions
{
    public string SigningKey { get; set; } = "";
    public string Lifetime { get; set; } = "00:10:00";
    public string Audience { get; set; } = "lis.exchange";
    public int RefreshExpirationInDays { get; set; } = 1; // correspond à "Refresh-ExpirationInDays"
}

public sealed record TokenResponse(string access_token, string refresh_token, int expires_in);
public sealed record LoginRequest(string username, string password);
public sealed record RefreshRequest(string refresh_token);

// ===========================
// Response factory (UNIQUE)
// ===========================
static class Api
{
    public static IResult Ok<T>(T data, string? correlationId = null)
        => Results.Ok(new ApiEnvelope<T>
        {
            Success = true,
            Data = data,
            Timestamp = DateTimeOffset.UtcNow,
            TraceId = Activity.Current?.Id ?? Guid.NewGuid().ToString("N"),
            CorrelationId = correlationId
        });

    public static IResult Ok<T>(IReadOnlyList<T> data, Pagination pagination, string? correlationId = null)
        => Results.Ok(new ApiEnvelope<IReadOnlyList<T>>
        {
            Success = true,
            Data = data,
            Pagination = pagination,
            Timestamp = DateTimeOffset.UtcNow,
            TraceId = Activity.Current?.Id ?? Guid.NewGuid().ToString("N"),
            CorrelationId = correlationId
        });

    public static IResult Ok<T>(IReadOnlyList<T> data, Pagination pagination, ApiMeta meta, string? correlationId = null)
        => Results.Ok(new ApiEnvelope<IReadOnlyList<T>>
        {
            Success = true,
            Data = data,
            Pagination = pagination,
            Meta = meta,
            Timestamp = DateTimeOffset.UtcNow,
            TraceId = Activity.Current?.Id ?? Guid.NewGuid().ToString("N"),
            CorrelationId = correlationId
        });

    public static IResult Error(int httpStatus, string code, string message, IEnumerable<ErrorDetail>? details = null)
        => Results.Json(new ApiEnvelope<object>
        {
            Success = false,
            Timestamp = DateTimeOffset.UtcNow,
            TraceId = Activity.Current?.Id ?? Guid.NewGuid().ToString("N"),
            Error = new ApiError
            {
                Code = code,
                Message = message,
                Details = details != null ? details.ToList() : new List<ErrorDetail>()
            }
        }, statusCode: httpStatus);

    public static (int page, int pageSize, (string code, string message, IEnumerable<ErrorDetail> details)? error) ValidatePaging(int? page, int? pageSize)
    {
        var p = page ?? 1;
        var ps = pageSize ?? 100;

        if (p < 1)
        {
            return (p, ps, ("VALIDATION_ERROR", "Invalid query parameters.",
                new[] { new ErrorDetail("page", "Must be >= 1.") }));
        }

        if (ps < 1 || ps > 1000)
        {
            return (p, ps, ("VALIDATION_ERROR", "Invalid query parameters.",
                new[] { new ErrorDetail("pageSize", "Must be between 1 and 1000.") }));
        }

        return (p, ps, null);
    }

    public static (DateTimeOffset? value, (string code, string message, IEnumerable<ErrorDetail> details)? error) ValidateSince(string? since)
    {
        if (string.IsNullOrWhiteSpace(since))
        {
            return (null, ("VALIDATION_ERROR", "Request validation failed.",
                new[] { new ErrorDetail("since", "The 'since' query parameter is required (ISO 8601 UTC).") }));
        }

        if (!DateTimeOffset.TryParse(
                since,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var parsed))
        {
            return (null, ("VALIDATION_ERROR", "Request validation failed.",
                new[] { new ErrorDetail("since", "Invalid datetime format. Use ISO 8601 (example: 2025-12-22T00:00:00Z).") }));
        }

        return (parsed.ToUniversalTime(), null);
    }

    public static string GetOrCreateCorrelationId(HttpContext ctx)
    {
        const string headerName = "X-Correlation-Id";

        if (ctx.Request.Headers.TryGetValue(headerName, out var values) &&
            !string.IsNullOrWhiteSpace(values.ToString()))
        {
            return values.ToString();
        }

        var generated = Guid.NewGuid().ToString();
        ctx.Response.Headers[headerName] = generated;
        return generated;
    }
}

public sealed class RefreshTokenStore
{
    // refresh_token -> entry
    private readonly Dictionary<string, RefreshTokenEntry> _tokens = new(StringComparer.Ordinal);
    private readonly object _lock = new();

    public void Save(RefreshTokenEntry entry)
    {
        lock (_lock) _tokens[entry.Token] = entry;
    }

    public bool TryGet(string token, out RefreshTokenEntry entry)
    {
        lock (_lock) return _tokens.TryGetValue(token, out entry!);
    }

    public void Revoke(string token)
    {
        lock (_lock) _tokens.Remove(token);
    }
}

public sealed record RefreshTokenEntry(
    string Token,
    string Username,
    DateTimeOffset ExpiresAtUtc,
    bool Revoked = false
);


static class LisJwt
{
    public static TimeSpan ParseLifetime(string lifetime)
        => TimeSpan.TryParse(lifetime, out var ts) ? ts : TimeSpan.FromMinutes(10);

    public static string CreateAccessToken(string username, LisJwtOptions opt)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(opt.SigningKey));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var now = DateTimeOffset.UtcNow;
        var expires = now.Add(ParseLifetime(opt.Lifetime));

        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, username),
            new Claim("usr", username)
        };

        var token = new JwtSecurityToken(
            issuer: null,
            audience: opt.Audience,
            claims: claims,
            notBefore: now.UtcDateTime,
            expires: expires.UtcDateTime,
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public static string CreateRefreshToken()
    {
        // opaque 64 bytes base64url
        var bytes = RandomNumberGenerator.GetBytes(64);
        return Base64UrlEncoder.Encode(bytes);
    }
}