static __always_inline file_info_t get_file_info(struct file *file)
{
    file_info_t file_info = {};
    if (file != NULL) {
        file_info.pathname_p = get_path_str(GET_FIELD_ADDR(file->f_path));
        file_info.ctime = get_ctime_nanosec_from_file(file);
        file_info.device = get_dev_from_file(file);
        file_info.inode = get_inode_nr_from_file(file);
    }
    return file_info;
}