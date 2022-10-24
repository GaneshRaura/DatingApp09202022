using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using API.Data;
using API.Entities;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using System.Text;
using API.DTOs;
using Microsoft.EntityFrameworkCore;
using API.Interfaces;

namespace API.Controllers
{
    public class AccountController : BaseApiController
    {
        private readonly DataContext _context;
        private readonly ITokenService _tokenService;

        public AccountController(DataContext context, ITokenService tokenService)
        {
            _context = context;
            _tokenService = tokenService;
        }
    
    [HttpPost("register")]
    public async Task<ActionResult<UserDto>> Register(RegisterDto registerDto)
    {
        if(await UserExists(registerDto.UserName))
        {
            return BadRequest("User Name is already exists");
        }

        using var hmac = new HMACSHA512();

        var user = new AppUser()
        {
            UserName = registerDto.UserName.ToLower(),
            PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDto.Password)),
            PasswordSalt = hmac.Key
        };

        _context.Users.Add(user);
        await _context.SaveChangesAsync();
        
        return new UserDto
        {
          Username = user.UserName,
          Token = _tokenService.CreateToken(user)   
        };
    }

    [HttpPost("login")]
    public async Task<ActionResult<UserDto>> login(LoginiDto loginDto)
    {
        var user = await _context.Users.SingleOrDefaultAsync(x => x.UserName == loginDto.Username);
        if(user == null) 
            {
                return Unauthorized("Invlaid User ID");
            }
        using var hmac = new HMACSHA512(user.PasswordSalt);
        var ComputedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.Password));

        for (int i = 0; i < ComputedHash.Length; i++)
            {
                if (ComputedHash[i] != user.PasswordHash[i])
                    {
                        return Unauthorized("Invalid User Name or Password");
                    }
            }
        
        return new UserDto
        {
          Username = user.UserName,
          Token = _tokenService.CreateToken(user)   
        };

    }

    private async Task<bool> UserExists(string username)
    {
        return await _context.Users.AnyAsync(x => x.UserName == username.ToLower());
    }
    }

}

