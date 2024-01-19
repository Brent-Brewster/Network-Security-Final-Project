public class FileResource extends SharedResource {

    public FileResource(String _owner, String _group, String _path) {
        super(_owner, _group, _path);
    }

    public FileResource(String _path) {
        super("", "", _path);
    }    
}
