using Entity.ModelsDto;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;

namespace UwingoIdentityMVC.Controllers
{
    public class RoleController : Controller
    {
        public async Task<IActionResult> Index(int pageNumber = 1, int pageSize = 10)
        {
            if (!User.HasClaim(c => c.Type == "Role" && c.Value == "GetAllRoles"))
                return StatusCode(403);

            List<RoleDto> roleList = new List<RoleDto>();
            HttpResponseMessage response = await GenerateClient.Client.GetAsync($"api/Role/GetPaginatedRoles?pageNumber={pageNumber}&pageSize={pageSize}");

            if (response.IsSuccessStatusCode)
            {
                var data = await response.Content.ReadAsStringAsync();
                roleList = JsonConvert.DeserializeObject<List<RoleDto>>(data);

                response = await GenerateClient.Client.GetAsync($"api/Role/GetRoleCount");

                if (response.IsSuccessStatusCode)
                {
                    var totalRole = await response.Content.ReadAsStringAsync();
                    int totalRecords = JsonConvert.DeserializeObject<int>(totalRole);

                    ViewBag.TotalRecords = totalRecords;
                    ViewBag.PageNumber = pageNumber;
                    if (totalRecords < pageSize) ViewBag.PageSize = totalRecords;
                    else ViewBag.PageSize = pageSize;
                }
            }
            else
                ViewBag.ErrorMessage = "An error occurred while fetching data.";
            
            return View(roleList);
        }
        public IActionResult Create()
        {
            if (!User.HasClaim(c => c.Type == "Role" && c.Value == "CreateRole"))
                return StatusCode(403);
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Create(RoleDto role)
        {
            if (!User.HasClaim(c => c.Type == "Role" && c.Value == "CreateRole"))
                return StatusCode(403);

            if (ModelState.IsValid)
            {
                var content = new StringContent(JsonConvert.SerializeObject(role), System.Text.Encoding.UTF8, "application/json");
                HttpResponseMessage response = await GenerateClient.Client.PostAsync("api/Role/CreateRole", content);

                if (response.IsSuccessStatusCode)
                    return RedirectToAction("Index");
                else
                    ModelState.AddModelError(string.Empty, "An error occurred while creating the role.");
            }
            return View(role);
        }

        public async Task<IActionResult> Edit(string id)
        {
            if (!User.HasClaim(c => c.Type == "Role" && c.Value == "EditRole"))
                return StatusCode(403);

            RoleDto role = null;
            HttpResponseMessage response = await GenerateClient.Client.GetAsync($"api/Role/GetRoleById/{id}");

            if (response.IsSuccessStatusCode)
            {
                var data = await response.Content.ReadAsStringAsync();
                role = JsonConvert.DeserializeObject<RoleDto>(data);
            }
            else
            {
                ViewBag.ErrorMessage = "An error occurred while fetching data.";
                return RedirectToAction(nameof(Index));
            }

            return View(role);
        }

        [HttpPost]
        public async Task<IActionResult> Edit([FromBody] RoleDto role)
        {
            if (!User.HasClaim(c => c.Type == "Role" && c.Value == "EditRole"))
                return StatusCode(403);

            if (ModelState.IsValid)
            {
                var content = new StringContent(JsonConvert.SerializeObject(role), System.Text.Encoding.UTF8, "application/json");
                HttpResponseMessage response = await GenerateClient.Client.PutAsync($"api/Role/UpdateRole/{role.Id}", content);

                if (response.IsSuccessStatusCode) return RedirectToAction("Index");
                else ModelState.AddModelError(string.Empty, "An error occurred while updating the role.");  
            }
            return View(role);
        }

        public async Task<IActionResult> Delete(string id)
        {
            if (!User.HasClaim(c => c.Type == "Role" && c.Value == "DeleteRole"))
                return StatusCode(403);

            HttpResponseMessage response = await GenerateClient.Client.DeleteAsync($"api/Role/DeleteRole/{id}");

            if (response.IsSuccessStatusCode)
                return RedirectToAction("Index");
            else
            {
                ViewBag.ErrorMessage = "An error occurred while deleting the role.";
                return RedirectToAction(nameof(Index));
            }
        }

        [HttpGet]
        public async Task<IActionResult> GetRoleClaims(string roleId)
        {
            if (!User.HasClaim(c => c.Type == "Role" && c.Value == "GetRoleClaims"))
                return StatusCode(403);
            // Tüm mevcut claim'leri çekiyor
            var apiAllClaims = $"api/Authentication/GetAllRoleClaims";
            HttpResponseMessage allClaimsResponse = await GenerateClient.Client.GetAsync(apiAllClaims);

            List<ClaimDto> allClaims = new List<ClaimDto>();
            if (allClaimsResponse.IsSuccessStatusCode)
            {
                var claims = await allClaimsResponse.Content.ReadAsStringAsync();
                allClaims = JsonConvert.DeserializeObject<List<ClaimDto>>(claims);
            }

            // Rolün sahip olduğu claim'leri çekiyor
            var apiRoleClaims = $"api/Authentication/GetRoleClaimsByRoleId/{roleId}";
            HttpResponseMessage roleClaimsResponse = await GenerateClient.Client.GetAsync(apiRoleClaims);

            List<ClaimDto> roleClaims = new List<ClaimDto>();
            if (roleClaimsResponse.IsSuccessStatusCode)
            {
                var claims = await roleClaimsResponse.Content.ReadAsStringAsync();
                roleClaims = JsonConvert.DeserializeObject<List<ClaimDto>>(claims);
            }

            // Rolün claim'lerine sahip olup olmadığını kontrol etmek için
            var model = allClaims.Select(claim => new ClaimViewModel
            {
                Type = claim.Type,
                Value = claim.Value,
                IsSelected = roleClaims.Any(rc => rc.Type == claim.Type && rc.Value == claim.Value)
            }).ToList();

            return PartialView("_RoleClaims", model);
        }

        [HttpPost]
        public async Task<IActionResult> UpdateRoleClaims([FromBody] RoleClaimsDto dto)
        {
            if (!User.HasClaim(c => c.Type == "Role" && c.Value == "EditRoleClaims"))
                return StatusCode(403);

            if (string.IsNullOrEmpty(dto.RoleId) || dto.Claims == null)
                return BadRequest("Bilinmeyen rol ID ya da yetkisi.");

            var backendUrl = $"api/Authentication/UpdateRoleClaims?roleId={dto.RoleId}";

            var content = new StringContent(JsonConvert.SerializeObject(dto.Claims), Encoding.UTF8, "application/json");

            var response = await GenerateClient.Client.PutAsync(backendUrl, content); // Use PUT for updates

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
    }
}
