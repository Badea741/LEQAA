﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BusinessLogic.Application.Models.Posts
{
    public record PostReadModel(
      string Title,
    byte[]? Image,
   string Content,
    string Username
);
}
