﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Entity.ModelsDto
{
    public class ApplicationDto
    {
        public Guid Id { get; set; }
        public string Name { get; set; }
        public string DbConnection { get; set; }
    }
}
