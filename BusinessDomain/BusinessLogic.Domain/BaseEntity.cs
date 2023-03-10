using System;
using System.ComponentModel.DataAnnotations;

namespace BusinessLogic.Domain
{
    public abstract class BaseEntity
    { 
       [Key]
        public Guid Id { get; set; }
        public DateTime CreationDate { get; set; }
    }
}