using Domain.DTO;
using Domain.Entities;
using Microsoft.AspNetCore.Mvc;
using WebApi29.Services.IServices;

namespace WebApi29.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UsuarioController : ControllerBase
    {
        private readonly IUsuarioServices _usuarioServices;

        public UsuarioController(IUsuarioServices usuarioServices)
        {
            _usuarioServices = usuarioServices;
        }

        [HttpGet]
        public async Task<IActionResult> GetUsers()
        {
            var response = await _usuarioServices.ObtenerUsuarios();
            return Ok(response);
        }

        [HttpGet("id")]
        public async Task<IActionResult> GetUser(int id)
        {
            return Ok(await _usuarioServices.ById(id));
        }

        [HttpPost]
        public async Task<IActionResult> PostUser(UsuarioRequest request)
        {
            var response = await _usuarioServices.Crear(request);
            return Ok(response);
        }

        [HttpPut("{id:int}")]
        public async Task<IActionResult> PutUser(int id, UsuarioRequest request)
        {
            var response = await _usuarioServices.Actualizar(id, request);
            return Ok(response);
        }

        [HttpDelete("{id:int}")]
        public async Task<IActionResult> DeleteUser(int id)
        {
            var response = await _usuarioServices.Eliminar(id);
            return Ok(response);
        }


    }
}