﻿using BusinessLogic.Application.CommandInterfaces;
using BusinessLogic.Application.Models.Hubs;
using BusinessLogic.Application.Models.Posts;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BusinessLogic.Application.Queries.Users.ViewUserHubs
{
    public record ViewUserPostsQuery(
 Guid userId

         ) : IQuery<List<HubReadModel>>;
}
