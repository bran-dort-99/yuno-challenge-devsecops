output "vpc_id"              { value = aws_vpc.cde.id }
output "vpc_cidr"            { value = aws_vpc.cde.cidr_block }
output "public_subnet_ids"   { value = aws_subnet.public[*].id }
output "private_app_subnet_ids"  { value = aws_subnet.private_app[*].id }
output "private_data_subnet_ids" { value = aws_subnet.private_data[*].id }
output "alb_sg_id"           { value = aws_security_group.alb.id }
output "app_sg_id"           { value = aws_security_group.app.id }
output "db_sg_id"            { value = aws_security_group.db.id }
