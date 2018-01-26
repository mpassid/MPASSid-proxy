package fi.okm.mpass.shibboleth.rest.data;

/**
 * An abstract base class for DTOs containing identifier and title.
 */
public abstract class TitledDTO {
    
    /** The identifier for this object. */
    private String id;
    
    /** The human-readable title for this object. */
    private String title;

    /**
     * @return Returns the id.
     */
    public String getId() {
        return id;
    }

    /**
     * @param id The id to set.
     */
    public void setId(String id) {
        this.id = id;
    }

    /**
     * @return Returns the title.
     */
    public String getTitle() {
        return title;
    }

    /**
     * @param title The title to set.
     */
    public void setTitle(String title) {
        this.title = title;
    }
}
