A script to scan network computers to find out which users have local admin rights.

7:53 AM 10/5/2009
  - modify line that if UserName not `Domain Admin` or `Administrator` we 
    denote the line a little more with ` <----- Review`

07:02 am 1/12/2009
  - rename all I/O to fla_??
  - wrote routines to search AD for all computers and output to list

 10:45 AM Thursday, April 16, 2009
  - purge old file first, then create new computer_names file
  - trap and log if computer_names file does not exist, record error in
    results file.
