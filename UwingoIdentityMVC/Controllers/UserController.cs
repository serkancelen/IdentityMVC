using Entity.Models;
using Entity.ModelsDto;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;

namespace UwingoIdentityMVC.Controllers
{
    //[Authorize(Roles = "Admin,TenantAdmin")]
    public class UserController : Controller
    {
        private readonly ILogger<UserController> _logger;
        public UserController(ILogger<UserController> logger)
        {
            _logger = logger;
        }
        public async Task<IActionResult> Index(int pageNumber = 1, int pageSize = 10)
        {
            if (!User.HasClaim(c => c.Type == "User" && c.Value == "GetAllUsers"))
                return StatusCode(403);
            // Kullanıcının rolünü kontrol et
            IEnumerable<UserDto> myUsers = await GetUser(pageNumber, pageSize);

            // Eğer myUsers boş değilse, View'a kullanıcıları gönder
            if (myUsers != null)
                return View(myUsers);

            // Eğer API çağrısı başarısız olursa veya kullanıcılar bulunamazsa, boş bir View döndür
            return View(new List<UserDto>());
        }


        public async Task<IActionResult> Create()
        {
            if (!User.HasClaim(c => c.Type == "User" && c.Value == "CreateUser"))
                return StatusCode(403);

            List<ApplicationDto> applications = new List<ApplicationDto>();
            List<RoleDto> roles = new List<RoleDto>();

            var isAdmin = User.IsInRole("Admin");
            var isTenantAdmin = User.IsInRole("TenantAdmin");
            var isUser = User.IsInRole("User");

            // Kullanıcı adminse tüm şirketlerin uygulamalarını getirelim
            if (isAdmin)
            {
                var response = await GenerateClient.Client.GetAsync("api/Application/GetAllApplications");
                if (response.IsSuccessStatusCode)
                {
                    var data = await response.Content.ReadAsStringAsync();
                    applications = JsonConvert.DeserializeObject<List<ApplicationDto>>(data);
                }
            }
            // TenantAdmin ise sadece kendi tenantına ait uygulamaları getirelim
            else if (isTenantAdmin)
            {
                var tenantId = User.Claims.FirstOrDefault(c => c.Type == "TenantId")?.Value;
                var response = await GenerateClient.Client.GetAsync($"api/Application/GetApplicationsByTenant/{tenantId}");
                if (response.IsSuccessStatusCode)
                {
                    var data = await response.Content.ReadAsStringAsync();
                    applications = JsonConvert.DeserializeObject<List<ApplicationDto>>(data);
                }
            }
            // User ise sadece bulunduğu applicationu getirelim
            else if (isUser)
            {
                var userName = User.Identity.Name;

                var response = await GenerateClient.Client.GetAsync($"api/Authentication/GetApplicationIdByUserName/{userName}");
                if (response.IsSuccessStatusCode)
                {
                    var data = await response.Content.ReadAsStringAsync();
                    string applicationId = JsonConvert.DeserializeObject<string>(data);

                    HttpResponseMessage response2 = await GenerateClient.Client.GetAsync($"api/Application/GetApplicationById/{applicationId}");

                    if (response2.IsSuccessStatusCode)
                    {
                        var application = await response2.Content.ReadAsStringAsync();
                        ApplicationDto applicationDto = JsonConvert.DeserializeObject<ApplicationDto>(application);
                        applications.Add(applicationDto);
                    }
                }
            }

            if (isAdmin)
            {
                roles.Add(new RoleDto { Id = "9970bb6b-2a25-4380-b695-c523b9c0476f", Name = "Admin" });
                roles.Add(new RoleDto { Id = "07434bdc-8ce9-450f-ac5c-e53308022a28", Name = "TenantAdmin" });
                roles.Add(new RoleDto { Id = "93997af7-441d-41ab-bee9-5ca5dc42100d", Name = "User" });
            }
            else if (isTenantAdmin)
            {
                roles.Add(new RoleDto { Id = "07434bdc-8ce9-450f-ac5c-e53308022a28", Name = "TenantAdmin" });
                roles.Add(new RoleDto { Id = "93997af7-441d-41ab-bee9-5ca5dc42100d", Name = "User" });
            }
            else if (isUser)
            {
                roles.Add(new RoleDto { Id = "93997af7-441d-41ab-bee9-5ca5dc42100d", Name = "User" });
            }


            return View(Tuple.Create(applications, roles));
        }

        [HttpPost]
        public async Task<IActionResult> Create(UserRegistrationDto myUser)
        {
            if (!User.HasClaim(c => c.Type == "User" && c.Value == "CreateUser"))
                return StatusCode(403);

            var apiRegister = "api/Authentication/register";
            var apiGetTenantId = $"api/Authentication/GetApplicationIdByUserName/{User.Identity.Name}";
            IEnumerable<UserDto> myUsers;
            // Kullanıcı adından ApplicationId'yi al
            HttpResponseMessage appResponse = await GenerateClient.Client.GetAsync(apiGetTenantId);

            if (appResponse.IsSuccessStatusCode)
            {
                var appData = await appResponse.Content.ReadAsStringAsync();
                var applicationId = JsonConvert.DeserializeObject<Guid>(appData);

                // applicationId'yi UserRegistrationDto'ya ata
                myUser.ApplicationId = applicationId;

                // Kullanıcıyı kaydet
                HttpResponseMessage registerResponse = await GenerateClient.Client.PostAsJsonAsync(apiRegister, myUser);

                if (registerResponse.IsSuccessStatusCode)
                {
                    myUsers = await GetUser(1, 10);
                    return View("Index", myUsers);
                }

                else
                    ViewBag.Message = "Kullanıcı kaydı başarısız oldu.";

            }
            else
                ViewBag.Message = "applicationId alınamadı.";

            myUsers = await GetUser(1, 10);
            return View("Index", myUsers);
        }
        public async Task<IActionResult> Edit(string id)
        {
            if (!User.HasClaim(c => c.Type == "User" && c.Value == "EditUser"))
                return StatusCode(403);

            var apiGetUser = $"api/Authentication/GetUserById/{id}";
            HttpResponseMessage userResponse = await GenerateClient.Client.GetAsync(apiGetUser);

            if (userResponse.IsSuccessStatusCode)
            {
                var userData = await userResponse.Content.ReadAsStringAsync();
                var myUser = JsonConvert.DeserializeObject<UserDto>(userData);

                return View(myUser);
            }

            return RedirectToAction("Index");
        }

        [HttpPost]
        public async Task<IActionResult> Edit([FromBody] UserDto myUser)
        {
            if (!User.HasClaim(c => c.Type == "User" && c.Value == "UpdateUser"))
                return StatusCode(403);

            var apiUpdateUser = $"api/Authentication/UpdateUser";

            HttpResponseMessage updateResponse = await GenerateClient.Client.PutAsJsonAsync(apiUpdateUser, myUser);

            if (updateResponse.IsSuccessStatusCode)
                return RedirectToAction("Index");
            else
                ViewBag.Message = "Kullanıcı güncellemesi başarısız oldu.";

            return View(myUser);
        }

        public async Task<IActionResult> Delete(Guid id)
        {
            if (!User.HasClaim(c => c.Type == "User" && c.Value == "DeleteUser"))
                return StatusCode(403);

            var apiDeleteUser = $"api/Authentication/DeleteUser/{id}";

            HttpResponseMessage deleteResponse = await GenerateClient.Client.DeleteAsync(apiDeleteUser);

            if (deleteResponse.IsSuccessStatusCode)
                return RedirectToAction("Index");
            else
            {
                ViewBag.Message = "Kullanıcı silme işlemi başarısız oldu.";
                return RedirectToAction("Index");
            }
        }

        public async Task<IActionResult> GetAllUserClaims()
        {
            if (!User.HasClaim(c => c.Type == "User" && c.Value == "GetUserClaims"))
                return StatusCode(403);

            var apiUC = $"api/Authentication/GetAllClaims";
            HttpResponseMessage httpResponse = await GenerateClient.Client.GetAsync(apiUC);

            if (httpResponse.IsSuccessStatusCode)
            {
                var claims = await httpResponse.Content.ReadAsStringAsync();
                List<ClaimDto> allUserClaims = JsonConvert.DeserializeObject<List<ClaimDto>>(claims);

                return Json(allUserClaims);
            }
            return RedirectToAction("Index");
        }


        public async Task<IActionResult> GetUserClaims(string userId)
        {
            if (!User.HasClaim(c => c.Type == "User" && c.Value == "GetUserClaims"))
                return StatusCode(403);
            // Tüm mevcut claim'leri çekin
            var apiAllClaims = $"api/Authentication/GetAllUserClaims";
            HttpResponseMessage allClaimsResponse = await GenerateClient.Client.GetAsync(apiAllClaims);

            List<ClaimDto> allClaims = new List<ClaimDto>();
            if (allClaimsResponse.IsSuccessStatusCode)
            {
                var claims = await allClaimsResponse.Content.ReadAsStringAsync();
                allClaims = JsonConvert.DeserializeObject<List<ClaimDto>>(claims);
            }

            // Kullanıcının sahip olduğu claim'leri çekin
            var apiUserClaims = $"api/Authentication/GetUserClaimsByUserId/{userId}";
            HttpResponseMessage userClaimsResponse = await GenerateClient.Client.GetAsync(apiUserClaims);

            List<ClaimDto> userClaims = new List<ClaimDto>();
            if (userClaimsResponse.IsSuccessStatusCode)
            {
                var claims = await userClaimsResponse.Content.ReadAsStringAsync();
                userClaims = JsonConvert.DeserializeObject<List<ClaimDto>>(claims);
            }

            // Kullanıcı claim'lerine sahip olup olmadığını kontrol etmek için
            var model = allClaims.Select(claim => new ClaimViewModel
            {
                Type = claim.Type,
                Value = claim.Value,
                IsSelected = userClaims.Any(uc => uc.Type == claim.Type && uc.Value == claim.Value)
            }).ToList();

            return PartialView("_UserClaims", model);
        }

        [HttpPost]
        public async Task<IActionResult> UpdateUserClaims([FromBody] UserClaimsDto dto)
        {
            if (!User.HasClaim(c => c.Type == "User" && c.Value == "EditUserClaims"))
                return StatusCode(403);

            if (string.IsNullOrEmpty(dto.UserId) || dto.Claims == null)
                return BadRequest("Bilinmeyen kullanıcıID ya da yetkisi.");

            // Backend URL, assuming this is your backend's address
            var backendUrl = $"api/Authentication/UpdateUserClaims?userId={dto.UserId}";

            var client = GenerateClient.Client;

            var content = new StringContent(JsonConvert.SerializeObject(dto.Claims), Encoding.UTF8, "application/json");

            var response = await client.PutAsync(backendUrl, content); // Use PUT for updates

            if (response.IsSuccessStatusCode)
            {
                var result = await response.Content.ReadAsStringAsync();
                return Ok(result);
            }
            else
            {
                var error = await response.Content.ReadAsStringAsync();
                return StatusCode((int)response.StatusCode, error);
            }
        }

        private async Task<IEnumerable<UserDto>> GetUser(int pageNumber = 1, int pageSize = 10)
        {
            var userRole = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Role)?.Value;

            IEnumerable<UserDto> myUsers = null;

            if (userRole == "Admin")
            {
                // Eğer kullanıcı Admin ise, tüm kullanıcıları getir
                var apiGetAllUsers = $"api/Authentication/GetPaginatedUsers?pageNumber={pageNumber}&pageSize={pageSize}";
                HttpResponseMessage allUsersResponse = await GenerateClient.Client.GetAsync(apiGetAllUsers);

                if (allUsersResponse.IsSuccessStatusCode)
                {
                    var users = await allUsersResponse.Content.ReadAsStringAsync();
                    myUsers = JsonConvert.DeserializeObject<IEnumerable<UserDto>>(users);

                    if (myUsers.Count() > 0)
                    {
                        int totalRecords = myUsers.Count();

                        ViewBag.TotalRecords = totalRecords;
                        ViewBag.PageNumber = pageNumber;
                        if (totalRecords < pageSize) ViewBag.PageSize = totalRecords;
                        else ViewBag.PageSize = pageSize;
                    }
                }
            }
            else if (userRole == "TenantAdmin" || userRole == "User")
            {
                // Eğer kullanıcı TenantAdmin ise, kendi ApplicationId'sine bağlı olan kullanıcıları getir
                var apiGetApptId = $"api/Authentication/GetApplicationIdByUserName/{User.Identity.Name}";
                HttpResponseMessage tenantResponse = await GenerateClient.Client.GetAsync(apiGetApptId);

                if (tenantResponse.IsSuccessStatusCode)
                {
                    var applicationData = await tenantResponse.Content.ReadAsStringAsync();
                    var applicationId = JsonConvert.DeserializeObject<Guid>(applicationData);

                    var apiGetUsersByApplicationId = $"api/Authentication/GetPaginatedUsersByApplicationId/{applicationId}?pageNumber={pageNumber}&pageSize={pageSize}";
                    HttpResponseMessage usersResponse = await GenerateClient.Client.GetAsync(apiGetUsersByApplicationId);

                    if (usersResponse.IsSuccessStatusCode)
                    {
                        var users = await usersResponse.Content.ReadAsStringAsync();
                        myUsers = JsonConvert.DeserializeObject<IEnumerable<UserDto>>(users);

                        if (myUsers.Count() > 0)
                        {
                            int totalRecords = myUsers.Count();
                            ViewBag.TotalRecords = totalRecords;
                            ViewBag.PageNumber = pageNumber;
                            if (totalRecords < pageSize) ViewBag.PageSize = totalRecords;
                            else ViewBag.PageSize = pageSize;
                        }
                    }
                }
            }
            return myUsers;
        }
    }
}